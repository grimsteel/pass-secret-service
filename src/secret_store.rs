use std::{borrow::Cow, collections::HashMap, path::Path, sync::{Arc, RwLock}};

use nanoid::nanoid;
use redb::{Database, MultimapTableDefinition, ReadableTable, TableDefinition};
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

const PASS_SUBDIR: &'static str = "secret-service";
const ATTRIBUTES_DB: &'static str = "attributes.db";

/// open a db contained within the given PasswordStore
async fn open_db(pass: &PasswordStore, path: impl AsRef<Path>) -> Result<Database> {
    let db_file = pass.open_file(path).await?
        .into_std().await;
    Ok(redb::Builder::new()
        .create_file(db_file).map_err(|e| Into::<redb::Error>::into(e))?)
}

/// convert a string to a valid ASCII slug
pub fn slugify(string: &str) -> String {
    let mut slugified = Vec::<u8>::with_capacity(string.len());

    // no two dashes in row
    let mut after_dash = true;

    for ch in string.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            after_dash = false;
            slugified.push(ch.to_ascii_lowercase() as u8);
        } else if !after_dash {
            // add a dash for all other chars
            after_dash = true;
            slugified.push(b'-')
        }
    }

    slugified.shrink_to_fit();

    // Safety: all chars pushed to the vec are ASCII
    unsafe { String::from_utf8_unchecked(slugified) }
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

        let has_default_collection = collections.contains_key("default");

        let db = open_db(&pass, &format!("{PASS_SUBDIR}/collections.redb")).await?;
        
        let store = Self {
            pass,
            collection_dbs: RwLock::new(collections),
            db: Arc::new(db)
        };

        // initialize the default store if necessary
        if !has_default_collection {
            store.create_collection(Some("Default".into()), Some("default".into()));
        }

        Ok(store)
    }

    async fn get_current_collections(pass: &PasswordStore) -> Result<HashMap<String, Database>> {
        let mut collections = HashMap::new();
        
        for (_, id) in pass.list_items(PASS_SUBDIR).await?
            .into_iter()
            .filter(|(file_type, _)| file_type.is_dir())
        {
            // make the DB for this collection
            let db_path = Path::new(PASS_SUBDIR).join(&id).join(ATTRIBUTES_DB);
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

        let collection_id = spawn_blocking(move || -> std::result::Result<_, redb::Error> {
            let tx = db.begin_write()?;
            let mut aliases = tx.open_table(ALIASES_TABLE)?;
            let mut labels = tx.open_table(LABELS_TABLE)?;

            let had_provided_label = label.is_some();
            let label = label.map(Cow::Owned).unwrap_or("Untitled Collection".into());

            // an existing alias
            let existing_id = if let Some(alias) = alias.as_ref() {
                if let Some(collection_id) = aliases.get(alias.as_str())? {
                    let id = collection_id.value();
                    
                    // update the label if we were given one or there isn't one already
                    // in the 2nd case, it just becomes Untitled Collection
                    if had_provided_label || labels.get(id)?.is_none() {
                        labels.insert(id, label.as_ref());
                    }
                    
                    Some(id.to_string())
                } else { None }
            } else { None };

            // if we couldn't find an existing ID, make a new collection
            let id = if let Some(id) = existing_id { id } else {
                
                let id = format!("{}-{}", slugify(&label), nanoid!(4));

                // set the label and alias
                if let Some(alias) = alias.as_ref() {
                    aliases.insert(alias.as_str(), id.as_str())?;
                }
                labels.insert(id.as_str(), label.as_ref())?;

                id
            };

            drop(aliases);
            drop(labels);
            tx.commit();

            Ok(id)
        }).await.unwrap()?;

        let mut collections = self.collection_dbs.write().unwrap();

        if !collections.contains_key(&collection_id) {
            // we need to actually create this collection

            let mut collection_path = Path::new(PASS_SUBDIR).join(&collection_id);
            self.pass.make_dir(&collection_path).await?;

            collection_path.push(ATTRIBUTES_DB);
            let db = open_db(&self.pass, collection_path).await?;

            collections.insert(collection_id.clone(), db);
        }

        Ok(collection_id)
    }
}
