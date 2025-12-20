use std::{
    collections::HashMap,
    fmt::Debug,
    fs::Metadata,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::{error::Result, pass::PasswordStore};

pub mod redb;
mod redb_imps;
//mod json;

pub const PASS_SUBDIR: &'static str = "secret-service";

pub const NANOID_ALPHABET: [char; 63] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '_',
];

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

/// get the directory for the given collection id
pub fn get_collection_dir(collection_id: &str) -> PathBuf {
    Path::new(PASS_SUBDIR).join(collection_id)
}

#[async_trait]
pub trait SecretStore<'a>: Debug + DynClone {
    async fn new(pass: &'a PasswordStore) -> Result<Self>
    where
        Self: Sized;
    fn get_pass(&self) -> &'a PasswordStore;
    async fn get_label(&self, collection: Arc<String>) -> Result<String>;
    async fn set_label(&self, collection_id: Arc<String>, label: String) -> Result;
    async fn list_all_aliases(&self) -> Result<HashMap<String, Vec<String>>>;
    async fn list_aliases_for_collection(&self, collection: Arc<String>) -> Result<Vec<String>>;
    async fn get_alias(&self, alias: Arc<String>) -> Result<String>;
    async fn set_alias(&self, alias: Arc<String>, collection: Option<String>) -> Result<()>;
    async fn collections(&self) -> Vec<String>;
    async fn create_collection(
        &self,
        label: Option<String>,
        alias: Option<String>,
    ) -> Result<String>;
    async fn delete_collection(&self, collection_id: Arc<String>) -> Result;
    async fn search_all_collections(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<String>>>;
    async fn search_collection(
        &self,
        collection_id: Arc<String>,
        attributes: Arc<HashMap<String, String>>,
    ) -> Result<Vec<String>>;
    async fn stat_collection(&self, collection_id: &str) -> Result<Metadata>;
    async fn list_secrets(&self, collection_id: &str) -> Result<Vec<String>>;
    async fn read_secret(
        &self,
        collection_id: &str,
        secret_id: &str,
        can_prompt: bool,
    ) -> Result<Vec<u8>>;
    async fn read_secret_attrs(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
    ) -> Result<HashMap<String, String>>;
    async fn delete_secret(&self, collection: Arc<String>, secret: Arc<String>) -> Result<()>;
    async fn stat_secret(&self, collection_id: &str, secret_id: &str) -> Result<Metadata>;
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

dyn_clone::clone_trait_object!(<'a> SecretStore<'a>);
