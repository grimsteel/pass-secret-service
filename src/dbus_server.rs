use std::{collections::HashMap, fmt::Display};

use tokio::sync::mpsc::{self, Receiver, Sender};
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

#[derive(Debug)]
pub struct Service<'a> {
    store: SecretStore<'a>,
    connection: Connection,
    collection_rx: Receiver<()>
}

#[derive(Clone, Debug)]
struct Collection {
    tx: Sender<()>
}

struct Item;
struct Session;
struct Prompt;

impl<'a> Service<'a> {
    pub async fn init(connection: Connection, pass: &'a PasswordStore) -> Result<Self> {
        let store = SecretStore::new(pass).await?;
        // setup the collection channel
        let (collection_tx, collection_rx) = mpsc::channel(4);

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
                let c = Collection { tx: collection_tx.clone() };

                // add the aliases
                for alias in aliases_reverse.remove(&collection).into_iter().flatten() {
                    let path = alias_path(alias).unwrap();
                    object_server.at(path, c.clone()).await?;
                }

                let path = collection_path(collection).unwrap();
                object_server.at(path, c).await?;

                // TODO: items
            }
        }
        
        Ok(Service {
            store,
            connection,
            collection_rx
        })
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
    ) -> fdo::Result<(ObjectPath, ObjectPath)> {
        // stringify the labelg
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        // slugify the alias and handle the case where it's empty
        let alias = slugify(&alias);
        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias).await?;
        let collection_path = collection_path(id).unwrap();

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

        let collection = collection.as_ref();
        // get just the collection ID
        let target = if collection == EMPTY_PATH {
            None
        } else {
            collection
                .strip_prefix("/org/freedesktop/secrets/collection/")
                .map(|s| s.to_string())
        };
        self.store.set_alias(alias, target).await?;
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
impl Collection {
    
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}
