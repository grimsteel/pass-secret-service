use std::{collections::HashMap, sync::Arc};

use zbus::{
    fdo, interface,
    message::Header,
    object_server::SignalContext,
    zvariant::{Dict, ObjectPath, Value},
    Connection, ObjectServer,
};

use crate::{
    error::{Error, Result},
    secret_store::SecretStore,
};

use super::{
    item::Item, session::Session, utils::{
        alias_path, collection_path, secret_alias_path, secret_path, time_to_int, try_interface,
        Secret, EMPTY_PATH,
    }
};

#[derive(Clone, Debug)]
pub struct Collection<'a> {
    pub store: SecretStore<'a>,
    pub id: Arc<String>,
}

impl<'a> Collection<'a> {
    fn make_item(&self, id: String) -> Item<'a> {
        Item {
            id: Arc::new(id),
            collection_id: self.id.clone(),
            store: self.store.clone(),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection<'static> {
    async fn delete(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath> {
        let secrets = self.store.list_secrets(&*self.id).await?;

        // remove this collection from the object server
        if let Some(path) = collection_path(&*self.id) {
            try_interface(object_server.remove::<Self, _>(&path).await)?;

            // emit the collection deleted event
            connection
                .emit_signal(
                    Option::<String>::None,
                    "/org/freedesktop/secrets",
                    "org.freedesktop.Secret.Service",
                    "CollectionDeleted",
                    &(path,),
                )
                .await?;
        }
        for secret in &secrets {
            if let Some(path) = secret_path(&*self.id, secret) {
                try_interface(object_server.remove::<Item, _>(path).await)?;
            }
        }
        // remove all aliases
        for alias in self
            .store
            .list_aliases_for_collection(self.id.clone())
            .await?
        {
            if let Some(path) = alias_path(&alias) {
                try_interface(object_server.remove::<Self, _>(path).await)?;
            }
            for secret in &secrets {
                if let Some(path) = secret_alias_path(&alias, secret) {
                    try_interface(object_server.remove::<Item, _>(path).await)?;
                }
            }
        }

        // delete the collection from the store
        self.store.delete_collection(self.id.clone()).await?;

        Ok(EMPTY_PATH)
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> Result<Vec<ObjectPath>> {
        let items = self
            .store
            .search_collection(self.id.clone(), Arc::new(attributes))
            .await?;
        let paths = items.into_iter().filter_map(collection_path).collect();

        Ok(paths)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, Value<'_>>,
        secret: Secret,
        replace: bool,
        #[zbus(signal_context)] signal_context: SignalContext<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(ObjectPath, ObjectPath)> {
        let secret_value =
            try_interface(object_server.interface::<_, Session>(&secret.session).await)?
                .ok_or(Error::InvalidSession)?
                .get()
                .await
                .decrypt(secret, &header)?;

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|l| l.downcast_ref::<String>().ok());
        let attrs = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|a| a.downcast_ref::<Dict>().ok())
            .and_then(|a| HashMap::<String, String>::try_from(a).ok())
            .unwrap_or_default();
        let attrs = Arc::new(attrs);

        let secret_id = if replace {
            // replace the secret with the matching attrs
            let matching_secret = self
                .store
                .search_collection(self.id.clone(), attrs.clone())
                .await?;
            if let Some(secret_id) = matching_secret.into_iter().nth(0).map(Arc::new) {
                // update the secret/label
                self.store
                    .set_secret(&*self.id, &*secret_id, secret_value)
                    .await?;
                if let Some(label) = label {
                    self.store
                        .set_secret_label(self.id.clone(), secret_id.clone(), label)
                        .await?;
                }

                let path = secret_path(&*self.id, &*secret_id).unwrap();
                Self::item_changed(&signal_context, path.clone()).await?;

                // no need to add to the object server
                return Ok((path, EMPTY_PATH));
            } else {
                self.store
                    .create_secret(self.id.clone(), label, secret_value, attrs)
                    .await?
            }
        } else {
            self.store
                .create_secret(self.id.clone(), label, secret_value, attrs)
                .await?
        };

        let path = secret_path(&*self.id, &secret_id).unwrap();
        let item = self.make_item(secret_id);

        // add to all aliases too
        for alias in self
            .store
            .list_aliases_for_collection(self.id.clone())
            .await?
        {
            if let Some(path) = secret_alias_path(&alias, &*item.id) {
                object_server.at(&path, item.clone()).await?;
            }
        }
        // add the item to the object server
        object_server.at(&path, item).await?;

        Self::item_created(&signal_context, path.clone()).await?;

        // no prompt needed for GPG encryption
        Ok((path, EMPTY_PATH))
    }

    #[zbus(property)]
    async fn items(&self) -> fdo::Result<Vec<ObjectPath>> {
        Ok(self
            .store
            .list_secrets(&*self.id)
            .await?
            .into_iter()
            // get the full path of the secret
            .filter_map(|id| secret_path(&*self.id, &id))
            .collect())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self.store.get_label(self.id.clone()).await?)
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        self.store.set_label(self.id.clone(), label).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        // we don't support locking
        false
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;

        Ok(time_to_int(metadata.created()))
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_collection(&self.id).await?;

        Ok(time_to_int(metadata.modified()))
    }

    #[zbus(signal)]
    async fn item_created(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;
}
