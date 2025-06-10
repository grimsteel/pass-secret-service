use std::{collections::HashMap, sync::Arc};

use zbus::{fdo, interface, message::Header, object_server::InterfaceDeref, zvariant::ObjectPath, Connection, ObjectServer};

use crate::{
    error::{Error, Result},
    secret_store::SecretStore,
};

use super::{
    session::Session,
    utils::{
        collection_path, secret_alias_path, secret_path, time_to_int, try_interface, Secret,
        EMPTY_PATH,
    },
};

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: SecretStore<'a>,
}

impl<'a> Item<'a> {
    fn path(&self) -> ObjectPath {
        secret_path(&*self.collection_id, &*self.id).unwrap()
    }

    async fn broadcast_collection_signal(&self, connection: &Connection, name: &str) -> Result {
        connection
            .emit_signal(
                Option::<String>::None,
                collection_path(&*self.collection_id).unwrap(),
                "org.freedesktop.Secret.Collection",
                name,
                &(self.path(),),
            )
            .await?;
        Ok(())
    }

    pub async fn read_with_session(&self, header: &Header<'_>, session: &InterfaceDeref<'_, Session>) -> Result<Secret> {
        let secret_value = self
            .store
            .read_secret(&*self.collection_id, &*self.id, true)
            .await?;

        session.encrypt(secret_value, header)
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item<'static> {
    async fn delete(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath> {
        // delete from the stoer
        self.store
            .delete_secret(self.collection_id.clone(), self.id.clone())
            .await?;

        self.broadcast_collection_signal(connection, "ItemDeleted")
            .await?;

        // delete the objects off of dbus
        try_interface(object_server.remove::<Self, _>(self.path()).await)?;

        for alias in self
            .store
            .list_aliases_for_collection(self.collection_id.clone())
            .await?
        {
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
        session: ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(Secret, )> {
        Ok((self.read_with_session(
            &header,
            &try_interface(object_server.interface::<_, Session>(&session).await)?
                .ok_or(Error::InvalidSession)?
                .get()
                .await
        ).await?, ))
    }

    async fn set_secret(
        &self,
        secret: Secret,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<()> {
        let secret_value =
            try_interface(object_server.interface::<_, Session>(&secret.session).await)?
                .ok_or(Error::InvalidSession)?
                .get()
                .await
                .decrypt(secret, &header)?;

        self.store
            .set_secret(&*self.collection_id, &*self.id, secret_value)
            .await?;

        self.broadcast_collection_signal(connection, "ItemChanged")
            .await?;

        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let attributes = self
            .store
            .read_secret_attrs(self.collection_id.clone(), self.id.clone())
            .await?;
        Ok(attributes)
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        attributes: HashMap<String, String>,
        //#[zbus(connection)] connection: &Connection
    ) -> fdo::Result<()> {
        self.store
            .set_secret_attrs(self.collection_id.clone(), self.id.clone(), attributes)
            .await?;

        //self.broadcast_collection_signal(connection, "ItemChanged");

        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self
            .store
            .get_secret_label(self.collection_id.clone(), self.id.clone())
            .await?)
    }

    #[zbus(property)]
    async fn set_label(
        &mut self,
        label: String,
        //#[zbus(connection)] connection: &Connection
    ) -> fdo::Result<()> {
        self.store
            .set_secret_label(self.collection_id.clone(), self.id.clone(), label)
            .await?;

        //self.broadcast_collection_signal(connection, "ItemChanged");

        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self
            .store
            .stat_secret(&*self.collection_id, &*self.id)
            .await?;
        Ok(time_to_int(metadata.created()))
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self
            .store
            .stat_secret(&*self.collection_id, &*self.id)
            .await?;
        Ok(time_to_int(metadata.modified()))
    }
}
