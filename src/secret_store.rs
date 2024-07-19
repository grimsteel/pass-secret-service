use std::{borrow::Cow, collections::HashMap, fmt::Debug, fs::Metadata, path::Path, sync::Arc};

use nanoid::nanoid;
use redb::{Database, MultimapTableDefinition, ReadableTable, TableDefinition};
use tokio::{runtime::Handle, sync::RwLock, task::spawn_blocking};

use crate::{
    error::{ignore_nonexistent_table, IntoResult, Result},
    pass::PasswordStore,
    redb_imps::RedbHashMap,
};

// Collection tables

// (key, value) --> secrets
const ATTRIBUTES_TABLE: MultimapTableDefinition<(&str, &str), &str> =
    MultimapTableDefinition::new("attributes");
const ATTRIBUTES_TABLE_REVERSE: TableDefinition<&str, RedbHashMap<&str, &str>> =
    TableDefinition::new("attributes-reverse");

// collection id --> label
const LABELS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("labels");
// collection alias -> id
const ALIASES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("aliases");

const PASS_SUBDIR: &'static str = "secret-service";
const ATTRIBUTES_DB: &'static str = "attributes.redb";

const NANOID_ALPHABET: [char; 63] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '_',
];

type RedbResult<T> = std::result::Result<T, redb::Error>;
/// open a db contained within the given PasswordStore
async fn open_db(pass: &PasswordStore, path: impl AsRef<Path>) -> Result<Database> {
    let db_file = pass.open_file(path).await?.into_std().await;
    Ok(redb::Builder::new()
        .create_file(db_file)
        .map_err(|e| Into::<redb::Error>::into(e))?)
}

/// convert a string to a valid ASCII slug
pub fn slugify(string: &str) -> String {
    let mut slugified = Vec::<u8>::with_capacity(string.len());

    // no two underscores in row
    let mut after_underscore = true;

    for ch in string.chars() {
        if ch.is_ascii_alphanumeric() {
            after_underscore = false;
            slugified.push(ch.to_ascii_lowercase() as u8);
        } else if !after_underscore {
            // add an underscore for all other chars
            after_underscore = true;
            slugified.push(b'_')
        }
    }

    slugified.shrink_to_fit();

    // Safety: all chars pushed to the vec are ASCII
    unsafe { String::from_utf8_unchecked(slugified) }
}

/// search a collection for the given attributes
/// returns a vec of secret IDs
pub fn search_collection(
    attrs: &HashMap<String, String>,
    db: &Database,
) -> RedbResult<Vec<String>> {
    if attrs.len() == 0 {
        return Ok(vec![]);
    };

    let tx = db.begin_read()?;
    let attributes = ignore_nonexistent_table!(tx.open_multimap_table(ATTRIBUTES_TABLE), vec![]);
    let attributes_reverse =
        ignore_nonexistent_table!(tx.open_table(ATTRIBUTES_TABLE_REVERSE), vec![]);

    let mut attr_iter = attrs.into_iter();

    // get the secrets which fit the first K/V attr pair
    let initial_matches = attributes.get(
        attr_iter
            .next()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .unwrap(),
    )?;

    // filter the items from there
    initial_matches
        .map(|r| -> RedbResult<_> {
            let secret_id_guard = r?;
            let secret_id = secret_id_guard.value();
            // get the attributes for this secret
            if let Some(secret_attrs) = attributes_reverse.get(secret_id)? {
                let secret_attrs = secret_attrs.value();
                // make sure it's a subset of the remaining `attrs`
                for (k, v) in attr_iter.clone() {
                    if secret_attrs.get(k.as_str()) != Some(&v.as_str()) {
                        return Ok(None);
                    };
                }
                Ok(Some(secret_id.to_owned()))
            } else {
                Ok(None)
            }
        })
        .filter_map(|item| item.transpose())
        .collect::<RedbResult<Vec<_>>>()
}

#[derive(Debug, Clone)]
pub struct SecretStore<'a> {
    pass: &'a PasswordStore,
    collection_dbs: Arc<RwLock<HashMap<String, Database>>>,
    db: Arc<Database>,
}

impl<'a> SecretStore<'a> {
    pub async fn new(pass: &'a PasswordStore) -> Result<Self> {
        let collections = Self::get_current_collections(pass).await?;

        let has_default_collection = collections.contains_key("default");

        let db = open_db(&pass, &format!("{PASS_SUBDIR}/collections.redb")).await?;

        let store = Self {
            pass,
            collection_dbs: Arc::new(RwLock::new(collections)),
            db: Arc::new(db),
        };

        // initialize the default store if necessary
        if !has_default_collection {
            store
                .create_collection(Some("Default".into()), Some("default".into()))
                .await?;
        }

        Ok(store)
    }

    async fn get_current_collections(pass: &PasswordStore) -> Result<HashMap<String, Database>> {
        let mut collections = HashMap::new();

        for (_, id) in pass
            .list_items(PASS_SUBDIR)
            .await?
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

    pub async fn get_label(&self, collection_id: Arc<String>) -> Result<Option<String>> {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            let tx = db.begin_read()?;
            let table = ignore_nonexistent_table!(tx.open_table(LABELS_TABLE), None);
            Ok(table.get(collection_id.as_str())?.map(|a| a.value().into()))
        })
        .await
        .unwrap()?)
    }

    pub async fn set_label(&self, collection_id: Arc<String>, label: String) -> Result {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            let tx = db.begin_write()?;
            let mut table = tx.open_table(LABELS_TABLE)?;
            table.insert(collection_id.as_str(), &*label)?;
            drop(table);
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap()?)
    }

    pub async fn aliases(&self) -> Result<HashMap<String, String>> {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            // open the aliases table
            let tx = db.begin_read()?;
            let table = ignore_nonexistent_table!(tx.open_table(ALIASES_TABLE), HashMap::new());
            table
                .iter()?
                .map(|i| {
                    let (k, v) = i?;
                    Ok((k.value().into(), v.value().into()))
                })
                .collect()
        })
        .await
        .unwrap()?)
    }

    pub async fn get_alias(&self, alias: String) -> Result<Option<String>> {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            // open the aliases table
            let tx = db.begin_read()?;
            let table = ignore_nonexistent_table!(tx.open_table(ALIASES_TABLE), None);
            Ok(table.get(alias.as_str())?.map(|v| v.value().into()))
        })
        .await
        .unwrap()?)
    }

    pub async fn set_alias(&self, alias: String, target: Option<String>) -> Result {
        let db = self.db.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            // open the aliases table
            let tx = db.begin_write()?;
            let mut table = tx.open_table(ALIASES_TABLE)?;

            if let Some(target) = target {
                table.insert(alias.as_str(), target.as_str())?;
            } else {
                // remove it
                table.remove(alias.as_str())?;
            }
            drop(table);
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap()?)
    }

    pub async fn collections(&self) -> Vec<String> {
        self.collection_dbs
            .read()
            .await
            .keys()
            .map(|a| a.to_owned())
            .collect()
    }

    /// create a collection, with an optional label and alias
    /// returns the created collection name
    /// if `label` is `None`, the collection will be called "Unttiled Collection"
    pub async fn create_collection(
        &self,
        label: Option<String>,
        alias: Option<String>,
    ) -> Result<String> {
        // I assume aliases are case sensitive

        let db = self.db.clone();

        let collection_id = spawn_blocking(move || -> RedbResult<_> {
            let tx = db.begin_write()?;
            let mut aliases = tx.open_table(ALIASES_TABLE)?;
            let mut labels = tx.open_table(LABELS_TABLE)?;

            let had_provided_label = label.is_some();
            let label = label
                .map(Cow::Owned)
                .unwrap_or("Untitled Collection".into());

            // an existing alias
            let existing_id = if let Some(alias) = alias.as_ref() {
                if let Some(collection_id) = aliases.get(alias.as_str())? {
                    let id = collection_id.value();

                    // update the label if we were given one or there isn't one already
                    // in the 2nd case, it just becomes Untitled Collection
                    if had_provided_label || labels.get(id)?.is_none() {
                        labels.insert(id, label.as_ref())?;
                    }

                    Some(id.to_string())
                } else {
                    None
                }
            } else {
                None
            };

            // if we couldn't find an existing ID, make a new collection
            let id = if let Some(id) = existing_id {
                id
            } else {
                let id = format!("{}_{}", slugify(&label), nanoid!(4, &NANOID_ALPHABET));

                // set the label and alias
                if let Some(alias) = alias.as_ref() {
                    aliases.insert(alias.as_str(), id.as_str())?;
                }
                labels.insert(id.as_str(), label.as_ref())?;

                id
            };

            drop(aliases);
            drop(labels);
            tx.commit()?;

            Ok(id)
        })
        .await
        .unwrap()?;

        let mut collections = self.collection_dbs.write().await;

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

    /// search all collections for secrets matching the given attributes
    /// returns a map of collection id to items
    pub async fn search_all_collections(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let collections = self.collection_dbs.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            let cols = collections.blocking_read();
            cols.iter()
                .map(|(id, db)| {
                    // search each collection
                    Ok((id.to_owned(), search_collection(&attributes, db)?))
                })
                .collect()
        })
        .await
        .unwrap()?)
    }

    /// search the specific collection for secrets matching the given attributes
    pub async fn search_collection(
        &self,
        collection_id: Arc<String>,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<String>> {
        let collections = self.collection_dbs.clone();
        Ok(spawn_blocking(move || {
            let cols = collections.blocking_read();
            if let Some(db) = cols.get(collection_id.as_ref()) {
                search_collection(&attributes, db)
            } else {
                Ok(vec![])
            }
        })
        .await
        .unwrap()?)
    }

    /// get the filesystem metadata for this collection
    pub async fn stat_collection(&self, collection_id: &str) -> Result<Metadata> {
        // just use the attributes db file rather than actually calculating the last modified date
        let collection_path = Path::new(PASS_SUBDIR)
            .join(&collection_id)
            .join(ATTRIBUTES_DB);
        Ok(self.pass.stat_file(collection_path).await?)
    }

    pub async fn list_secrets(&self, collection_id: &str) -> Result<Vec<String>> {
        let collection_path = Path::new(PASS_SUBDIR).join(&collection_id);

        Ok(self
            .pass
            .list_items(collection_path)
            .await?
            .into_iter()
            .filter_map(|(file_type, name)| {
                if file_type.is_file() && name.ends_with(".gpg") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect())
    }

    /// decrypt a secret stored in the given collection with the given id
    /// if can_prompt is true, a gpg prompt may show
    pub async fn read_secret(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
        can_prompt: bool,
    ) -> Result<Vec<u8>> {
        let secret_path = Path::new(PASS_SUBDIR)
            .join(&*collection_id)
            .join(&*secret_id);

        Ok(self.pass.read_password(secret_path, can_prompt).await?)
    }

    /// read the attributes for the given secret
    pub async fn read_secret_attrs(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
    ) -> Result<HashMap<String, String>> {
        // delete the attributes
        let collections = self.collection_dbs.clone();
        Ok(spawn_blocking(move || -> RedbResult<_> {
            let cols = collections.blocking_read();
            if let Some(db) = cols.get(&*collection_id) {
                let tx = db.begin_read()?;
                let attributes_table_reverse = ignore_nonexistent_table!(
                    tx.open_table(ATTRIBUTES_TABLE_REVERSE),
                    HashMap::new()
                );

                let secret_id = secret_id.as_str();

                if let Some(attrs) = attributes_table_reverse.get(secret_id)? {
                    let attrs = attrs.value();
                    return Ok(attrs
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect());
                }
            }
            // it's fine if the DB doesn't exist

            Ok(HashMap::new())
        })
        .await
        .unwrap()?)
    }

    /// remove a secret and its attributes
    pub async fn delete_secret(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
    ) -> Result {
        let secret_path = Path::new(PASS_SUBDIR)
            .join(&*collection_id)
            .join(&*secret_id);

        // delete the password
        self.pass.delete_password(secret_path).await?;

        // delete the attributes
        let collections = self.collection_dbs.clone();
        spawn_blocking(move || -> RedbResult<()> {
            let cols = collections.blocking_read();
            if let Some(db) = cols.get(&*collection_id) {
                let tx = db.begin_write()?;
                let mut attributes_table = tx.open_multimap_table(ATTRIBUTES_TABLE)?;
                let mut attributes_table_reverse = tx.open_table(ATTRIBUTES_TABLE_REVERSE)?;

                let secret_id = secret_id.as_str();

                if let Some(attrs) = attributes_table_reverse.remove(secret_id)? {
                    let attrs = attrs.value();
                    for (k, v) in attrs {
                        attributes_table.remove((k, v), secret_id)?;
                    }
                };

                drop(attributes_table);
                drop(attributes_table_reverse);
                tx.commit()?;
            }
            // it's fine if the DB doesn't exist

            Ok(())
        })
        .await
        .unwrap()?;

        Ok(())
    }
}

impl SecretStore<'static> {
    pub async fn write_secret(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
        value: Vec<u8>,
        attributes: HashMap<String, String>,
    ) -> Result {
        let collection_dir = Path::new(PASS_SUBDIR).join(&*collection_id);
        let secret_path = collection_dir.join(&*secret_id);

        // write the password
        self.pass.write_password(secret_path, value).await?;

        let pass_store = self.pass;

        // write the attributes
        let collections = self.collection_dbs.clone();
        spawn_blocking(move || -> Result {
            let mut cols = collections.blocking_write();

            // get the db or make a new one
            let db = if let Some(db) = cols.get(&*collection_id) {
                db
            } else {
                let db_path = collection_dir.join(ATTRIBUTES_DB);
                let db = Handle::current()
                    .block_on(async move { open_db(pass_store, db_path).await })?;
                // add it to the map
                cols.entry((*collection_id).to_owned()).or_insert(db)
            };

            let tx = db.begin_write().into_result()?;
            let mut attributes_table = tx.open_multimap_table(ATTRIBUTES_TABLE).into_result()?;
            let mut attributes_table_reverse =
                tx.open_table(ATTRIBUTES_TABLE_REVERSE).into_result()?;

            let value = secret_id.as_str();

            // remove existing attributes for this secret
            if let Some(existing_attrs) = attributes_table_reverse.get(value).into_result()? {
                for (k, v) in existing_attrs.value() {
                    attributes_table.remove((k, v), value).into_result()?;
                }
            }

            let attributes_ref = attributes
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<HashMap<_, _>>();

            // insert the new attributes
            for (k, v) in &attributes {
                attributes_table
                    .insert((k.as_str(), v.as_str()), value)
                    .into_result()?;
            }
            attributes_table_reverse
                .insert(value, attributes_ref)
                .into_result()?;

            drop(attributes_table);
            drop(attributes_table_reverse);
            tx.commit().map_err(|e| redb::Error::from(e))?;

            Ok(())
        })
        .await
        .unwrap()?;

        Ok(())
    }
}
