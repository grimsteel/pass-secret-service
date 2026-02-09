use dyn_clone::clone_box;
use log::{debug, trace};
use std::{collections::HashMap, sync::Arc};

use zbus::{
    fdo, interface,
    message::Header,
    object_server::SignalContext,
    zvariant::{Dict, ObjectPath, Value},
    Connection, ObjectServer,
};

use crate::{
    dbus_server::secret_transfer::Secret,
    error::{Error, Result},
    secret_store::SecretStore,
};

use super::{
    item::Item,
    session::Session,
    utils::{
        alias_path, collection_path, secret_alias_path, secret_path, time_to_int, try_interface,
        EMPTY_PATH,
    },
};

#[derive(Clone, Debug)]
pub struct Collection<'a> {
    pub store: Box<dyn SecretStore<'a> + Send + Sync>,
    pub id: Arc<String>,
}

impl<'a> Collection<'a> {
    fn make_item(&self, id: String) -> Item<'a> {
        Item {
            id: Arc::new(id),
            collection_id: self.id.clone(),
            store: clone_box(self.store.as_ref()),
            last_access: Default::default()
        }
    }

    async fn broadcast_self_signal<'b: 'a>(
        &self,
        connection: &Connection,
        name: &str,
        data_path: ObjectPath<'b>,
    ) -> Result {
        Self::broadcast_collection_signal(
            self.store.as_ref(),
            self.id.clone(),
            connection,
            name,
            data_path,
        )
        .await
    }

    /// emit signal on collection and all aliases
    pub async fn broadcast_collection_signal<'b, 'c>(
        store: &(dyn SecretStore<'c> + Send + Sync),
        collection_id: Arc<String>,
        connection: &Connection,
        name: &str,
        data_path: ObjectPath<'b>,
    ) -> Result {
        let collection_path = collection_path(&collection_id).unwrap();
        trace!(
            "Broadcasting signal {} on {} and all aliases for {}",
            name,
            collection_path,
            data_path
        );

        let signal_data = (data_path,);

        // add to all aliases too
        for alias in store
            .list_aliases_for_collection(collection_id.clone())
            .await?
        {
            if let Some(path) = alias_path(&alias) {
                connection
                    .emit_signal(
                        Option::<String>::None,
                        path,
                        "org.freedesktop.Secret.Collection",
                        name,
                        &signal_data,
                    )
                    .await?;
            }
        }

        // main collection path
        connection
            .emit_signal(
                Option::<String>::None,
                &collection_path,
                "org.freedesktop.Secret.Collection",
                name,
                &signal_data,
            )
            .await?;

        // service change
        connection
            .emit_signal(
                Option::<String>::None,
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
                "CollectionChanged",
                &(collection_path,),
            )
            .await?;

        Ok(())
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection<'static> {
    async fn delete(
        &'_ self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath<'_>> {
        debug!(
            "Deleting collection {} for {}",
            self.id,
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into())
        );
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

    async fn search_items(&'_ self, attributes: HashMap<String, String>) -> Result<Vec<ObjectPath<'_>>> {
        let items = self
            .store
            .search_collection(self.id.clone(), Arc::new(attributes))
            .await?;
        let paths = items
            .into_iter()
            .filter_map(|item| secret_path(&*self.id, &item))
            .collect();

        Ok(paths)
    }

    async fn create_item(
        &'_ self,
        properties: HashMap<String, Value<'_>>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(ObjectPath<'_>, ObjectPath<'_>)> {
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

                // fire signal
                self.broadcast_self_signal(connection, "ItemChanged", path.clone())
                    .await?;

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

        // fire signal
        self.broadcast_self_signal(connection, "ItemCreated", path.clone())
            .await?;

        // no prompt needed for GPG encryption
        Ok((path, EMPTY_PATH))
    }

    #[zbus(property)]
    async fn items(&'_ self) -> fdo::Result<Vec<ObjectPath<'_>>> {
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
        // the collection does not need to be unlocked for it to be used. gpg will prompt automatically
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
