use std::{borrow::Cow, collections::{HashMap, HashSet}, fs::Metadata, io::SeekFrom, path::{Path, PathBuf}, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::from_slice;
use tokio::{fs::{File, remove_file}, io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt}, sync::Mutex};
use nanoid::nanoid;

use crate::{error::{OptionNoneNotFound, Result}, pass::PasswordStore, secret_store::{NANOID_ALPHABET, PASS_SUBDIR, SecretStore, slugify}};

const COLLECTION_SETTINGS_FILE: &'static str = "collection.json";

/// Collection settings and item settings are stored in separate files, so this object is never serialized/deserialized
#[derive(Debug)]
struct Collection {
    settings: CollectionSettings,
    file: File,
    items: HashMap<String, Item>
}

impl Collection {
    pub fn collection_dir(collection_id: &str) -> PathBuf {
        Path::new(PASS_SUBDIR).join(collection_id)
    }
    
    /// Save a collection settings file
    async fn save_settings(&mut self) -> Result {
        let buf = serde_json::to_vec(&self.settings)?;
        
        self.file.set_len(buf.len() as u64).await?;
        self.file.seek(SeekFrom::Start(0)).await?;
        self.file.write_all(&buf[..]);
        
        Ok(())
    }
    
    /// Search items for the given attributes
    fn search_items(&self, attrs: &HashMap<String, String>) -> Vec<String> {
        self.items.iter()
            .filter(|(_id, item)| {
                // make sure all attributes given match
                attrs.iter().all(|(k, v)| item.settings.attrs.get(k).is_some_and(|v0| v0 == v))
            })
            .map(|(id, _item)| id.into())
            .collect()
    }
}

#[derive(Debug)]
struct Item {
    settings: ItemSettings,
    file: File
}

// JSON object type definitions

/// JSON object stored in collection.json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectionSettings {
    label: String,
    aliases: HashSet<String>
}

/// Used when a collections.json file doesn't exist in a collection
impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            label: "Untitled Collection".into(),
            aliases: HashSet::new()
        }
    }
}

/// JSON object stored in [id].json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ItemSettings {
    label: String,
    attrs: HashMap<String, String>
}

impl Default for ItemSettings {
    fn default() -> Self {
        Self {
            label: "Untitled Secret".into(),
            attrs: HashMap::new()
        }
    }
}

#[derive(Debug, Clone)]
/// SecretStore implementation in plain-text JSON files stored along secrets.
/// Currently used implementation.
pub struct JsonSecretStore<'a> {
    pass: &'a PasswordStore,
    collections: Arc<Mutex<HashMap<String, Collection>>>,
}

impl<'a> JsonSecretStore<'a> {
    /// Open a JSON file and read its current contents
    async fn read_json_file<T: for <'b> Deserialize<'b> + Default>(pass: &PasswordStore, path: impl AsRef<Path>) -> Result<(File, T)> {
        let mut file = pass.open_file(path).await?;
        // read
        let size = file.metadata().await?.len() as usize;
        if size == 0 {
            // empty
            return Ok((file, T::default()))
        }
        let mut buf = Vec::with_capacity(size);
        file.read_to_end(&mut buf).await?;
        // parse
        Ok((file, from_slice(&buf[..])?))
    }
}

#[async_trait]
impl<'a> SecretStore<'a> for JsonSecretStore<'a> {
    async fn new(pass: &'a PasswordStore) -> Result<Self> {        
        let mut collections = HashMap::new();
        
        // get all collection directories
        for (_, id) in pass
            .list_items(PASS_SUBDIR)
            .await?
            .into_iter()
            .filter(|(file_type, _)| file_type.is_dir()) {
                let collection_dir = Collection::collection_dir(&id);
        
                let collection_settings_path = collection_dir
                    .join(COLLECTION_SETTINGS_FILE);
                
                // read initial contents
                let (file, settings) = Self::read_json_file(pass, collection_settings_path).await?;
                
                let mut items = HashMap::new();
                
                // parse all collection items
                for (_, secret_filename) in pass
                    .list_items(&collection_dir)
                    .await?
                    .into_iter()
                    // convert filename into pathbuf for easier use
                    .map(|(file_type, filename)| (file_type, PathBuf::from(filename)))
                    // filter by files ending in .gpg
                    .filter(|(file_type, filename)| {
                        file_type.is_file() && filename.extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("gpg"))
                    })
                {
                    let item_settings_path = collection_dir
                        .join(secret_filename.with_extension("json"));
                    
                    let (item_file, item_settings) = Self::read_json_file(pass, item_settings_path).await?;
                    
                    // remove extension for normal id
                    let item_id = secret_filename.file_stem()
                        .expect("Items have a filename")
                        .to_str()
                        .expect("Item filenames are valid Unicode");
                    
                    items.insert(item_id.into(), Item {
                        settings: item_settings,
                        file: item_file
                    });
                }
                
                
                collections.insert(id, Collection {
                    settings,
                    file,
                    items
                });
            }
        
        Ok(Self {
            pass,
            collections: Arc::new(Mutex::new(collections))
        })
    }
    
    fn get_pass(&self) -> &'a PasswordStore {
        self.pass
    }
    async fn get_label(&self, collection: Arc<String>) -> Result<String> {
        Ok(
            self.collections.lock().await
                .get(collection.as_ref()).into_not_found()?
                .settings.label
                .to_string()
        )
    }
    async fn set_label(&self, collection_id: Arc<String>, label: String) -> Result {
        let mut collections = self.collections.lock().await;
        let collection = collections
            .get_mut(collection_id.as_ref()).into_not_found()?;
        
        collection.settings.label = label;
        collection.save_settings().await?;
        Ok(())
    }
    async fn list_all_aliases(&self) -> Result<HashMap<String, Vec<String>>> {
        let collections = self.collections.lock().await;
        
        Ok(collections.iter()
            .map(|(id, coll)| {
                (id.clone(), coll.settings.aliases.iter().cloned().collect())
            })
            .collect())
    }
    async fn list_aliases_for_collection(&self, collection: Arc<String>) -> Result<Vec<String>> {
        Ok(
            self.collections.lock().await
                .get(collection.as_ref()).into_not_found()?
                .settings.aliases
                .iter().cloned().collect()
        )
    }
    /// get collection associated with given alias
    async fn get_alias(&self, alias: Arc<String>) -> Result<String> {
        let collections = self.collections.lock().await;
        
        collections.iter()
            .find_map(|(id, coll)| {
                if coll.settings.aliases.contains(alias.as_ref()) {
                    Some(id.into())
                } else {
                    None
                }
            })
            .into_not_found()
    }
    async fn set_alias(&self, alias: Arc<String>, collection: Option<String>) -> Result<()> {
        let mut collections = self.collections.lock().await;
        
        // remove old alias
        for (id, col) in collections.iter_mut() {
            let mut save = false;
            
            // remove old alias
            if col.settings.aliases.remove(alias.as_ref()) {
                // save this collection
                save = !save;
            }
            
            if collection.as_ref().is_some_and(|c| c == id) {
                col.settings.aliases.insert(alias.to_string());
                save = !save;
            }
            
            if save {
                col.save_settings().await?;
            }
        }
        
        Ok(())
    }
    async fn collections(&self) -> Vec<String> {
        self.collections.lock().await.keys().cloned().collect()
    }
    async fn create_collection(
        &self,
        label: Option<String>,
        alias: Option<String>,
    ) -> Result<String> {
        let mut collections = self.collections.lock().await;
        
        // use existing alias
        if let Some(alias) = &alias {
            if let Some((id, existing_collection)) = collections.iter_mut()
                .find(|c| c.0 == alias)
            {
                // update label if provided
                if let Some(label) = label {
                    existing_collection.settings
                        .label = label;
                }
                
                existing_collection.save_settings().await?;
                
                // don't create new collection
                return Ok(id.to_owned())
            }
        }
        
        let label = label
            .map(Cow::Owned)
            .unwrap_or("Untitled collection".into());
        
        // try to use label as ID
        let id = if collections.contains_key(label.as_ref()) {
            // append random chars to make unique
            format!("{}_{}", slugify(&label), nanoid!(4, &NANOID_ALPHABET))
        } else {
            label.clone().into_owned()
        };
        
        // create aliases set
        let aliases = HashSet::new();
        if let Some(alias) = alias {
            for (_, col) in collections.iter_mut()
                .filter(|c| c.0 == &alias)
            {
                col.settings.aliases.remove(&alias);
                col.save_settings().await?;
            }
            
            aliases.insert(alias);
        }
        
        let settings = CollectionSettings {
            label: label.into_owned(),
            aliases
        };
        
        // TODO: write to file/make dir
        
        collections.insert(id.clone(), Collection {
            settings,
            file: File::create_new("a"),
            items: HashMap::new()
        });
        
        Ok(id)
    }
    async fn delete_collection(&self, collection_id: Arc<String>) -> Result {
        // remove from our HashMap
        self.collections.lock().await
            .remove(collection_id.as_ref()).into_not_found()?;
        // delete collection dir
        self.pass.remove_dir(Collection::collection_dir(collection_id.as_ref())).await?;
        
        Ok(())
    }
    async fn search_all_collections(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<String>>> {
        // repeat search_items on each collection
        Ok(self.collections.lock().await
            .iter()
            .map(|(id, collection)| (id.into(), collection.search_items(&attributes)))
            .collect())
    }
    async fn search_collection(
        &self,
        collection_id: Arc<String>,
        attributes: Arc<HashMap<String, String>>,
    ) -> Result<Vec<String>> {
        Ok(self.collections.lock().await
            .get(collection_id.as_ref()).into_not_found()?
            .search_items(attributes.as_ref()))
    }
    /// filesystem metadata for the collection settings file
    async fn stat_collection(&self, collection_id: &str) -> Result<Metadata> {
        Ok(self.collections.lock().await
            .get(collection_id).into_not_found()?
            .file.metadata().await?)
    }
    async fn list_secrets(&self, collection_id: &str) -> Result<Vec<String>> {
        Ok(self.collections.lock().await
            .get(collection_id).into_not_found()?
            .items.keys().cloned().collect())
    }
    /// read and decrypt secret
    async fn read_secret(
        &self,
        collection_id: &str,
        secret_id: &str,
        can_prompt: bool,
    ) -> Result<Vec<u8>> {
        let secret_path = Collection::collection_dir(collection_id).join(secret_id);
        Ok(self.pass.read_password(secret_path, can_prompt).await?)
    }
    async fn read_secret_attrs(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
    ) -> Result<HashMap<String, String>> {
        Ok(self.collections.lock().await
            .get(collection.as_ref()).into_not_found()?
            .items.get(secret.as_ref()).into_not_found()?
            .settings.attrs.clone())
    }
    async fn delete_secret(&self, collection: Arc<String>, secret: Arc<String>) -> Result {
        // remove from map
        self.collections.lock().await
            .get_mut(collection.as_ref()).into_not_found()?
            .items.remove(secret.as_ref()).into_not_found()?;
        let secret_id = Collection::collection_dir(collection.as_ref()).join(secret.as_ref());
        // delete secret
        self.pass.delete_password(&secret_id).await?;
        // delete attributes
        remove_file(self.pass.directory.join(secret_id).with_added_extension("json")).await?;
        Ok(())
    }
    async fn stat_secret(&self, collection_id: &str, secret_id: &str) -> Result<Metadata> {
        let secret_id = Collection::collection_dir(collection).join(secret);
        // stat secret file
        
    }
    async fn create_secret(
        &self,
        collection_id: Arc<String>,
        label: Option<String>,
        secret: Vec<u8>,
        attributes: Arc<HashMap<String, String>>,
    ) -> Result<String>;
    async fn set_secret(&self, collection_id: &str, secret_id: &str, value: Vec<u8>) -> Result;
    async fn set_secret_label(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
        label: String,
    ) -> Result<()>;
    async fn get_secret_label(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
    ) -> Result<String>;
    async fn set_secret_attrs(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
        attrs: HashMap<String, String>,
    ) -> Result;
}
