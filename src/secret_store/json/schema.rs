use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tokio::fs::File;

use crate::secret_store::{json::json_file::JsonFile, PASS_SUBDIR};

/// Collection settings and item settings are stored in separate files, so this object is never serialized/deserialized
#[derive(Debug)]
pub struct Collection {
    pub settings: CollectionSettings,
    pub file: File,
    pub items: HashMap<String, Item>,
}

impl Collection {
    pub fn collection_dir(collection_id: &str) -> PathBuf {
        Path::new(PASS_SUBDIR).join(collection_id)
    }

    /// Search items for the given attributes
    pub fn search_items(&self, attrs: &HashMap<String, String>) -> Vec<String> {
        self.items
            .iter()
            .filter(|(_id, item)| {
                // make sure all attributes given match
                attrs
                    .iter()
                    .all(|(k, v)| item.settings.attrs.get(k).is_some_and(|v0| v0 == v))
            })
            .map(|(id, _item)| id.into())
            .collect()
    }
}

impl JsonFile<CollectionSettings> for Collection {
    fn inner(&mut self) -> (&mut File, &CollectionSettings) {
        (&mut self.file, &self.settings)
    }
}

#[derive(Debug)]
pub struct Item {
    pub settings: ItemSettings,
    pub file: File,
}

impl JsonFile<ItemSettings> for Item {
    fn inner(&mut self) -> (&mut File, &ItemSettings) {
        (&mut self.file, &self.settings)
    }
}

// JSON object type definitions

/// JSON object stored in collection.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSettings {
    pub label: String,
    pub aliases: HashSet<String>,
}

/// Used when a collections.json file doesn't exist in a collection
impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            label: "Untitled Collection".into(),
            aliases: HashSet::new(),
        }
    }
}

/// JSON object stored in [id].json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSettings {
    pub label: String,
    pub attrs: HashMap<String, String>,
}

impl Default for ItemSettings {
    fn default() -> Self {
        Self {
            label: "Untitled Secret".into(),
            attrs: HashMap::new(),
        }
    }
}
