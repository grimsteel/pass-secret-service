use std::{collections::HashMap, fmt::Display, sync::Arc, time::SystemTime};

use tokio::{sync::mpsc::{self, Sender}, task};
use zbus::{
    fdo, interface,
    object_server::SignalContext,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
    Connection,
};

use crate::{
    error::Result, pass::PasswordStore, secret_store::{slugify, SecretStore}
};

const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

fn collection_path<'a, 'b, T: Display>(collection_id: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{collection_id}")).ok()
}
fn alias_path<'a, 'b, T: Display>(alias: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/aliases/{alias}")).ok()
}
fn try_interface<T>(result: zbus::Result<T>) -> zbus::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(zbus::Error::InterfaceNotFound) => Ok(None),
        Err(e) => Err(e)
    }
}

enum Message {
    CollectionDeleted(Arc<String>)
}

#[derive(Debug)]
pub struct Service<'a> {
    store: SecretStore<'a>,
    connection: Connection,
    collection_channel: Sender<Message>
}

#[derive(Clone, Debug)]
struct Collection<'a> {
    tx: Sender<Message>,
    store: SecretStore<'a>,
    id: Arc<String>
}

struct Item;
struct Session;
struct Prompt;

impl Service<'static> {
    pub async fn init(connection: Connection, pass: &'static PasswordStore) -> Result<Self> {
        let store = SecretStore::new(pass).await?;
        // setup the collection channel
        let (tx, mut rx) = mpsc::channel(4);

        {
            let object_server = connection.object_server();

            let aliases = store.aliases().await?;
            let mut aliases_reverse = aliases.into_iter()
                .fold(HashMap::<String, Vec<String>>::new(), |mut map, (alias, target)| {
                    {
                        if let Some(items) = map.get_mut(&alias) {
                            items.push(target);
                        } else {
                            map.insert(alias, vec![target]);
                        }
                    }
                    map
                });

            // add existing collections
            for collection in store.collections().await {
                let collection_aliases = aliases_reverse.remove(&collection).into_iter().flatten();
                let path = collection_path(&collection).unwrap();
                
                let c = Collection { tx: tx.clone(), store: store.clone(), id: Arc::new(collection) };

                // add the aliases
                for alias in collection_aliases {
                    let path = alias_path(alias).unwrap();
                    object_server.at(path, c.clone()).await?;
                }

                object_server.at(path, c).await?;

                // TODO: items
            }
        }

        let connection_2 = connection.clone();

        task::spawn(async move {
            // Handle notifications from the collections
            let signal_context = SignalContext::new(&connection_2, "/org/freedesktop/secrets")?;
            let object_server = connection_2.object_server();
            
            while let Some(msg) = rx.recv().await {
                match msg {
                    Message::CollectionDeleted(collection_id) => {
                        if let Some(path) = collection_path(collection_id) {
                            // remove the collection
                            try_interface(object_server.remove::<Collection, _>(&path).await)?;
                            // emit the signal
                            Self::collection_deleted(&signal_context, path).await?;
                        }
                    }
                }
            }

            zbus::Result::Ok(())
        });
        
        Ok(Service {
            store,
            connection,
            collection_channel: tx
        })
    }

    fn make_collection(&self, name: String) -> Collection<'static> {
        Collection { tx: self.collection_channel.clone(), id: Arc::new(name), store: self.store.clone() }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service<'static> {
    async fn open_session(&self, algorithm: String, input: OwnedValue) -> (Value, ObjectPath) {
        ("".into(), EMPTY_PATH)
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(signal_context)]
        signal: SignalContext<'_>
    ) -> fdo::Result<(ObjectPath, ObjectPath)> {
        // stringify the labelg
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        let object_server = self.connection.object_server();

        // slugify the alias and handle the case where it's empty
        let alias = slugify(&alias);
        
        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias.clone()).await?;
        let collection_path = collection_path(&id).unwrap();

        // if the collection here doesn't exist, create it and handle alises
        // the only reason it might exist is if they supplied an existing alias
        if try_interface(object_server.interface::<_, Collection>(&collection_path).await)?.is_none() {
            let c = self.make_collection(id);

            object_server.at(&collection_path, c.clone()).await?;
            
            // if they supplied an alias, handle it
            if let Some(alias) = alias {
                let alias_path = alias_path(&alias).unwrap();
                // remove the alias at this point
                try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

                object_server.at(&alias_path, c).await?;
            }

            Self::collection_created(&signal, collection_path.clone()).await?;
        }

        Ok((collection_path, EMPTY_PATH))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<ObjectPath>, Vec<ObjectPath>)> {
        let items = self.store.search_all_collections(attributes).await?;
        let paths = items
            .into_iter()
            .filter_map(collection_path)
            .collect();
        // we don't support locking
        Ok((paths, vec![]))
    }

    async fn lock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn unlock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn read_alias(&self, name: String) -> fdo::Result<ObjectPath> {
        let alias = slugify(&name);

        if let Some(target) = self.store.get_alias(alias).await?
            .as_ref().and_then(collection_path)
        {
            Ok(target)
        } else {
            Ok(EMPTY_PATH)
        }
    }

    async fn set_alias(&self, name: String, collection: OwnedObjectPath) -> fdo::Result<()> {
        let alias = slugify(&name);

        let alias_path = alias_path(&alias).unwrap();

        let collection = collection.as_ref();
        let object_server = self.connection.object_server();

        // remove the alias at this point
        try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;
        
        // TODO: Remove items
        
        let target_collection_id = if collection == EMPTY_PATH {
            None
        } else {
            let collection_interface = object_server.interface::<_, Collection>(&collection).await?
                .get().await
                .to_owned();
            object_server.at(&alias_path, collection_interface).await?;

            // TODO: add items

            // get just the ID
            collection
                .strip_prefix("/org/freedesktop/secrets/collection/")
                .map(|s| s.to_string())
        };
        // save this persistently
        self.store.set_alias(alias, target_collection_id).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<ObjectPath> {
        self.store
            .collections()
            .await
            .into_iter()
            .filter_map(|v| v.try_into().ok())
            .collect()
    }

    // signals

    #[zbus(signal)]
    async fn collection_created(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_modified(ctx: &SignalContext<'_>, path: ObjectPath<'_>)
        -> zbus::Result<()>;
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection<'static> {
    async fn delete(&self) -> ObjectPath {
        // notify the service
        let _ = self.tx.send(Message::CollectionDeleted(self.id.clone())).await;
        
        EMPTY_PATH
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<ObjectPath>> {
        let items = self.store.search_collection(self.id.clone(), attributes).await?;
        let paths = items
            .into_iter()
            .filter_map(collection_path)
            .collect();

        Ok(paths)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: (),
        replace: bool
    ) -> fdo::Result<(ObjectPath, ObjectPath)> {
        todo!()
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<ObjectPath> {
        todo!()
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self.store.get_label(self.id.clone()).await?.unwrap_or_else(|| "Untitled Collection".into()))
    }
    
    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        self.store.set_label(self.id.clone(), label).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool { false }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;
        let created = metadata.created().ok()
            // return 0 for times before the epoch or for platforms where this isn't supported
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|t| t.as_secs())
            .unwrap_or_default();

        Ok(created)
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;
        let modified = metadata.modified().ok()
            // return 0 for times before the epoch or for platforms where this isn't supported
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|t| t.as_secs())
            .unwrap_or_default();

        Ok(modified)
    }

    #[zbus(signal)]
    async fn item_created(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(ctx: &SignalContext<'_>, path: ObjectPath<'_>)
                                 -> zbus::Result<()>;
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}
