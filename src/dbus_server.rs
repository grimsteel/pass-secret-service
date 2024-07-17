use std::collections::HashMap;

use zbus::{fdo, interface, zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value}};

use crate::{error::Result, secret_store::SecretStore};

const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

struct Service {
    store: SecretStore
}

struct Collection;
struct Item;
struct Session;
struct Prompt;

type DBusResult<T> = std::result::Result<T, fdo::Error>;

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(&self, algorithm: String, input: OwnedValue) -> (Value, ObjectPath) {
        
    }

    async fn create_collection(&self, properties: HashMap<String, OwnedValue>, alias: String) -> (ObjectPath, ObjectPath) {
        
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> (Vec<ObjectPath>, Vec<ObjectPath>) {
        
    }

    async fn lock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn unlock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn read_alias(&self, name: String) -> DBusResult<ObjectPath> {
        if let Some(target) = self.store
            .get_alias(name).await?
            .and_then(|v| ObjectPath::try_from(v).ok())
        {
            Ok(target)
        } else {
            Ok(EMPTY_PATH)
        }
    }

    async fn set_alias(&self, name: String, collection: OwnedObjectPath) -> DBusResult<()> {
        let collection = collection.as_ref();
        let target = if collection == EMPTY_PATH { None } else { Some(collection.to_string()) };
        self.store.set_alias(name, target).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<ObjectPath> {
        self.store.collections()
            .into_iter()
            .filter_map(|v| v.try_into().ok())
            .collect()
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    
}


pub async fn init_service() -> Result<Service> {
    Ok(Service {
        store: SecretStore::new().await?
    })
}
