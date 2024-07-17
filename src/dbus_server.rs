use std::collections::HashMap;

use zbus::{
    fdo, interface,
    object_server::SignalContext,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value},
    Connection, ObjectServer,
};

use crate::{
    error::Result,
    secret_store::{slugify, SecretStore},
};

const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

pub struct Service {
    store: SecretStore,
    connection: Connection,
}

struct Collection;
struct Item;
struct Session;
struct Prompt;

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(&self, algorithm: String, input: OwnedValue) -> (Value, ObjectPath) {
        ("".into(), EMPTY_PATH)
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
    ) -> fdo::Result<(ObjectPath, ObjectPath)> {
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        let alias = slugify(&alias);
        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias).await?;
        let collection_path =
            ObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{id}")).unwrap();

        Ok((collection_path, EMPTY_PATH))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<ObjectPath>, Vec<ObjectPath>)> {
        let items = self.store.search_all_collections(attributes).await?;
        let paths = items
            .into_iter()
            .filter_map(|i| {
                ObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{i}")).ok()
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

    async fn read_alias(&self, name: String) -> fdo::Result<ObjectPath> {
        let alias = slugify(&name);

        if let Some(target) = self.store.get_alias(alias).await?.and_then(|v| {
            ObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{v}")).ok()
        }) {
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
impl Collection {}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}

pub async fn init_service(connection: Connection) -> Result<Service> {
    Ok(Service {
        store: SecretStore::new().await?,
        connection,
    })
}
