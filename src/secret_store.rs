use std::{collections::HashMap, path::Path, sync::RwLock};

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

/// open a db contained within the given PasswordStore
async fn open_db(pass: &PasswordStore, path: impl AsRef<Path>) -> Result<Database> {
    let db_file = pass.open_file(path).await?
        .into_std().await;
    Ok(redb::Builder::new()
        .create_file(db_file).map_err(|e| Into::<redb::Error>::into(e))?)
}

pub struct SecretStore {
    pass: PasswordStore,
    collection_dbs: RwLock<HashMap<String, Database>>,
    db: Database
}

impl SecretStore {
    pub async fn new() -> Result<Self> {
        let pass = PasswordStore::from_env()?;
        let collections = RwLock::new(Self::get_collections(&pass).await?);

        let db = open_db(&pass, "secret-store/collections.redb").await?;
        
        Ok(Self {
            pass,
            collection_dbs: collections,
            db
        })
    }

    async fn get_collections(pass: &PasswordStore) -> Result<HashMap<String, Database>> {
        let mut collections = HashMap::new();
        
        for (_, id) in pass.list_items("secret-store").await?
            .into_iter()
            .filter(|(file_type, _)| file_type.is_dir())
        {
            let db_path = Path::new("secret-store").join(&id).join("attributes.redb");
            let db = open_db(&pass, db_path).await?;
            collections.insert(id, db);
        }

        Ok(collections)
    }
}
