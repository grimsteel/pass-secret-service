use std::{collections::HashMap, sync::Arc};

use zbus::{fdo, interface, zvariant::ObjectPath, Connection, ObjectServer};

use crate::{error::Result, secret_store::SecretStore};

use super::utils::{collection_path, secret_alias_path, secret_path, time_to_int, try_interface, Secret, EMPTY_PATH};

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: SecretStore<'a>
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item<'static> {
    async fn delete(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer
    ) -> Result<ObjectPath> {
        // delete from the stoer
        self.store.delete_secret(self.collection_id.clone(), self.id.clone()).await?;

        let path = secret_path(&*self.collection_id, &*self.id).unwrap();

        // signal on the collection
        connection
            .emit_signal(
                Option::<String>::None,
                collection_path(&*self.collection_id).unwrap(),
                "org.freedesktop.Secret.Collection",
                "ItemDeleted",
                &(path.clone(), ),
            ).await?;

        // delete the objects off of dbus
        try_interface(object_server.remove::<Self, _>(path).await)?;

        for alias in self.store.list_aliases_for_collection(self.collection_id.clone()).await? {
            // delete from each alias
            if let Some(path) = secret_alias_path(&*alias, &*self.id) {
                try_interface(object_server.remove::<Self, _>(path).await)?;
            }
        }
        
        // no prompts required to delete
        Ok(EMPTY_PATH)
    }

    async fn get_secret(
        &self,
        session: ObjectPath<'_>
    ) -> Result<Secret> {
        // TODO: actually encrypt w/ session

        let secret = self.store.read_secret(&*self.collection_id, &*self.id, true).await?;

        Ok(Secret {
            session: session.into(),
            parameters: vec![],
            value: secret,
            content_type: "".into()
        })
    }

    async fn set_secret(
        &self,
        secret: Secret
    ) -> Result<()> {
        // TODO: actually decrypt w/ session
        self.store.set_secret(&*self.collection_id, &*self.id, secret.value).await?;
        
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool { true }

    #[zbus(property)]
    async fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let attributes = self.store.read_secret_attrs(self.collection_id.clone(), self.id.clone()).await?;
        Ok(attributes)
    }

    #[zbus(property)]
    async fn set_attributes(&mut self, attributes: HashMap<String, String>) -> fdo::Result<()> {
        self.store.set_secret_attrs(self.collection_id.clone(), self.id.clone(), attributes).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self.store.get_secret_label(self.collection_id.clone(), self.id.clone()).await?)
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        Ok(self.store.set_secret_label(self.collection_id.clone(), self.id.clone(), label).await?)
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_secret(&*self.collection_id, &*self.id).await?;
        Ok(time_to_int(metadata.created()))
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self.store.stat_secret(&*self.collection_id, &*self.id).await?;
        Ok(time_to_int(metadata.modified()))
    }
}
