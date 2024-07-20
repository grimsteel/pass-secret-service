use std::sync::Arc;

use zbus::interface;

use crate::secret_store::SecretStore;

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: SecretStore<'a>
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item<'static> {
}
