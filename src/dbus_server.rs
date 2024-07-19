use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    sync::Arc,
    time::SystemTime,
};

use zbus::{
    fdo, interface,
    object_server::SignalContext,
    zvariant::{DeserializeDict, ObjectPath, OwnedObjectPath, OwnedValue, SerializeDict, Type, Value},
    Connection, ObjectServer,
};

use crate::{
    error::Result,
    pass::PasswordStore,
    secret_store::{slugify, SecretStore},
};

const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

fn collection_path<'a, 'b, T: Display + Debug>(collection_id: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}"
    ))
    .ok()
}
fn secret_path<'a, 'b, T: Display + Debug>(
    collection_id: T,
    secret_id: T,
) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}/{secret_id}"
    ))
    .ok()
}
fn secret_alias_path<'a, 'b, T: Display + Debug>(
    alias: T,
    secret_id: T,
) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/aliases/{alias}/{secret_id}"
    ))
    .ok()
}
fn alias_path<'a, 'b, T: Display>(alias: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/aliases/{alias}")).ok()
}
fn try_interface<T>(result: zbus::Result<T>) -> zbus::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(zbus::Error::InterfaceNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}


#[derive(DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
struct Secret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String
}

#[derive(Debug)]
pub struct Service<'a> {
    store: SecretStore<'a>
}

#[derive(Clone, Debug)]
struct Collection<'a> {
    store: SecretStore<'a>,
    id: Arc<String>,
}

#[derive(Clone, Debug)]
struct Item;
struct Session;
struct Prompt {
    secret: Vec<u8>,
    attrs: HashMap<String, String>,
    label: Option<String>,
    replace: bool
}

impl Service<'static> {
    pub async fn init(connection: Connection, pass: &'static PasswordStore) -> Result<Self> {
        let store = SecretStore::new(pass).await?;

        {
            let object_server = connection.object_server();

            let mut aliases = store.list_all_aliases().await?;

            // add existing collections
            for collection in store.collections().await {
                let collection_aliases = aliases.remove(&collection).into_iter().flatten();
                let path = collection_path(&collection).unwrap();

                let secrets: Vec<_> = store.list_secrets(&collection).await?
                    .into_iter()
                    .map(|id| (id, Item))
                    .collect();

                // add the collection secrets
                for secret in &secrets {
                    if let Some(path) = secret_path(&collection, &secret.0) {
                        object_server.at(path, secret.1.clone()).await?;
                    }
                }

                let c = Collection {
                    store: store.clone(),
                    id: Arc::new(collection),
                };

                // add the aliases
                for alias in collection_aliases {
                    if let Some(path) = alias_path(&alias) {
                        object_server.at(path, c.clone()).await?;
                    }
                    // add the secrets under the alias
                    for secret in &secrets {
                        if let Some(path) = secret_alias_path(&alias, &secret.0) {
                            object_server.at(path, secret.1.clone()).await?;
                        }
                    }
                }
                // add the collection
                object_server.at(path, c).await?;
               
            }
        }

        Ok(Service {
            store,
        })
    }

    fn make_collection(&self, name: String) -> Collection<'static> {
        Collection {
            id: Arc::new(name),
            store: self.store.clone(),
        }
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
        #[zbus(signal_context)] signal: SignalContext<'_>,
        #[zbus(object_server)] object_server: &ObjectServer
    ) -> Result<(ObjectPath, ObjectPath)> {
        // stringify the labelg
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        // slugify the alias and handle the case where it's empty
        let alias = slugify(&alias);

        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias.clone()).await?;
        let collection_path = collection_path(&id).unwrap();

        // if the collection here doesn't exist, create it and handle alises
        // the only reason it might exist is if they supplied an existing alias
        if try_interface(
            object_server
                .interface::<_, Collection>(&collection_path)
                .await,
        )?
        .is_none()
        {
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
    ) -> Result<(Vec<ObjectPath>, Vec<ObjectPath>)> {
        let items = self.store.search_all_collections(attributes).await?;
        let paths = items
            .into_iter()
            .flat_map(|(col, secrets)| {
                secrets
                    .into_iter()
                    .filter_map(move |secret| secret_path(&col, &secret))
            })
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

    async fn read_alias(&self, name: String) -> Result<ObjectPath> {
        let alias = slugify(&name);

        if let Some(target) = self
            .store
            .get_alias(Arc::new(alias))
            .await?
            .as_ref()
            .and_then(collection_path)
        {
            Ok(target)
        } else {
            Ok(EMPTY_PATH)
        }
    }

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] object_server: &ObjectServer
    ) -> Result<()> {
        let alias = Arc::new(slugify(&name));

        let alias_path = alias_path(&alias).unwrap();

        let collection = collection.as_ref();

        // remove the alias at this point
        try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

        if let Some(old_target) = self.store.get_alias(alias.clone()).await? {
            let secrets = self.store.list_secrets(&old_target).await?;

            for secret in secrets {
                if let Some(path) = secret_alias_path(&*alias, &secret) {
                    try_interface(object_server.remove::<Item, _>(&path).await)?;
                }
            }
        }

        // TODO: Remove items

        let target_collection_id = if collection == EMPTY_PATH {
            None
        } else {
            let collection_interface = object_server
                .interface::<_, Collection>(&collection)
                .await?
                .get()
                .await
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
            .filter_map(collection_path)
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
    async fn delete(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer
    ) -> Result<ObjectPath> {

        let secrets = self.store
            .list_secrets(&*self.id)
            .await?;
        
        // remove this collection from the object server
        if let Some(path) = collection_path(&*self.id) {
            try_interface(object_server.remove::<Self, _>(&path).await)?;

            // emit the collection deleted event
            connection.emit_signal(
                Option::<String>::None,
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
                "CollectionDeleted",
                &(path, )
            ).await?;
        }
        for secret in &secrets {
            if let Some(path) = secret_path(&*self.id, secret) {
                try_interface(object_server.remove::<Item, _>(path).await)?;
            }
        }
        // remove all aliases
        for alias in self.store.list_aliases_for_collection(self.id.clone()).await? {
            if let Some(path) = alias_path(&alias) {
                try_interface(object_server.remove::<Self, _>(path).await)?;
            }
            for secret in &secrets {
                if let Some(path) = secret_alias_path(&alias, secret) {
                    try_interface(object_server.remove::<Item, _>(path).await)?;
                }
            }
        }
        
        // delete the collection from the store
        self.store.delete_collection(self.id.clone()).await?;

        Ok(EMPTY_PATH)
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> Result<Vec<ObjectPath>> {
        let items = self
            .store
            .search_collection(self.id.clone(), attributes)
            .await?;
        let paths = items.into_iter().filter_map(collection_path).collect();

        Ok(paths)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
    ) -> Result<(ObjectPath, ObjectPath)> {
        
        todo!()
    }

    #[zbus(property)]
    async fn items(&self) -> fdo::Result<Vec<ObjectPath>> {
        Ok(self
            .store
            .list_secrets(&*self.id)
            .await?
            .into_iter()
            // get the full path of the secret
            .filter_map(|id| secret_path(&*self.id, &id))
            .collect())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self
            .store
            .get_label(self.id.clone())
            .await?
            .unwrap_or_else(|| "Untitled Collection".into()))
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        self.store.set_label(self.id.clone(), label).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        // we don't support locking
        false
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;
        let created = metadata
            .created()
            .ok()
            // return 0 for times before the epoch or for platforms where this isn't supported
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|t| t.as_secs())
            .unwrap_or_default();

        Ok(created)
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;
        let modified = metadata
            .modified()
            .ok()
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
    async fn item_changed(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}
