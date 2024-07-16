use std::{path::Path, sync::RwLock};

use redb::{Database, MultimapTableDefinition, TableDefinition};

use crate::{error::Result, pass::PasswordStore};

// Collection tables

// (key, value) --> secrets
const ATTRIBUTES_TABLE: MultimapTableDefinition<(&str, &str), &str> = MultimapTableDefinition::new("attributes");
const ATTRIBUTES_TABLE_REVERSE: TableDefinition<&str, Vec<(&str, &str)>> = TableDefinition::new("attributes-reverse");

// collection id --> label
const LABELS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("labels");
// collection alias -> id
const ALIASES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("aliases");

pub struct SecretStore {
    pass: PasswordStore,
    collections: RwLock<Vec<Collection>>,
    db: Database
}

impl SecretStore {
    pub async fn new() -> Result<Self> {
        let pass = PasswordStore::from_env()?;
        let collections = RwLock::new(Self::get_collections(&pass).await?);

        let db_file = pass.open_file("secret-store/collections.redb").await?
            .into_std().await;
        let db = redb::Builder::new()
            .create_file(db_file).map_err(|e| Into::<redb::Error>::into(e))?;
        
        Ok(Self {
            pass,
            collections,
            db
        })
    }

    async fn get_collections(pass: &PasswordStore) -> Result<Vec<Collection>> {
        let mut collections = vec![];
        
        for item in pass.list_items("secret-store").await?
            .into_iter()
            .filter(|(file_type, _)| file_type.is_dir())
        {
            collections.push(Collection::from_id(item.1, pass).await?);
        }

        Ok(collections)
    }
}

struct Collection {
    id: String,
    db: Database
}

impl Collection {
    async fn from_id(id: String, pass: &PasswordStore) -> Result<Self> {
        let db_file = pass.open_file(Path::new("secret-store").join(&id)).await?
            .into_std().await; // ReDB is sync

        let db = redb::Builder::new()
            .create_file(db_file).map_err(|e| Into::<redb::Error>::into(e))?;

        Ok(Self {
            id,
            db
        })
    }
}
