use std::{collections::HashMap, path::Path, sync::{Arc, RwLock}};

use redb::{Database, Key, MultimapTableDefinition, ReadTransaction, TableDefinition, Value};
use tokio::task::spawn_blocking;

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
    db: Arc<Database>
}

impl SecretStore {
    pub async fn new() -> Result<Self> {
        let pass = PasswordStore::from_env()?;
        let collections = Self::get_current_collections(&pass).await?;

        let db = open_db(&pass, "secret-store/collections.redb").await?;
        
        Ok(Self {
            pass,
            collection_dbs: RwLock::new(collections),
            db: Arc::new(db)
        })
    }

    async fn get_current_collections(pass: &PasswordStore) -> Result<HashMap<String, Database>> {
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

    pub async fn get_alias(&self, alias: String) -> Result<Option<String>> {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> std::result::Result<_, redb::Error> {
            // open the aliases table
            let tx = db.begin_read()?;
            let table = match tx.open_table(ALIASES_TABLE) {
                Ok(t) => t,
                // table does not exist yet - that's ok
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into())
            };
            Ok(table.get(alias.as_str())?.map(|v| v.value().into()))
        }).await.unwrap()?)
    }

    
    pub async fn set_alias(&self, alias: String, target: Option<String>) -> Result {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> std::result::Result<_, redb::Error> {
            // open the aliases table
            let tx = db.begin_write()?;
            let mut table = tx.open_table(ALIASES_TABLE)?;

            if let Some(target) = target {
                table.insert(alias.as_str(), target.as_str());
            } else {
                // remove it
                table.remove(alias.as_str());
            }
            
            Ok(())
        }).await.unwrap()?)
    }

    pub fn collections(&self) -> Vec<String> {
        self.collection_dbs.read().unwrap()
            .keys()
            .map(|a| a.to_owned())
            .collect()
    }

    /// returns the created collection name
    pub async fn create_collection(&self, label: Option<String>, alias: Option<String>) -> Result<String> {
        // I assume aliases are case sensitive

        let db = self.db.clone();

        Ok(spawn_blocking(move || -> std::result::Result<_, redb::Error> {
            let tx = db.begin_write()?;
            let aliases = tx.open_table(ALIASES_TABLE);
            if let Some(alias) 
        }).await.unwrap()?
    }
}
