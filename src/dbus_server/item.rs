use jiff::Timestamp;
use log::debug;
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::{sync::RwLock, task::spawn_blocking};
use std::{collections::HashMap, sync::Arc};

use zbus::{
    Connection, ObjectServer, fdo::{self, DBusProxy}, interface, message::Header, names::{BusName, UniqueName}, object_server::InterfaceDeref, zvariant::{ObjectPath, Optional, Type}
};

use crate::{
    dbus_server::collection::Collection,
    error::{Error, Result},
    secret_store::SecretStore,
};

use super::{
    secret_transfer::Secret,
    session::Session,
    utils::{secret_alias_path, secret_path, time_to_int, try_interface, EMPTY_PATH},
};

#[derive(Type, Clone, Debug, Serialize, Deserialize, PartialEq)]
/// Holds information about the last process to access (decrypt) an item
pub struct SecretAccessor<'a> {
    #[serde(borrow)]
    pub dbus_name: Optional<UniqueName<'a>>,
    pub uid: u32,
    pub pid: u32,
    pub process_name: Optional<String>,
    // ms since epoch
    pub timestamp: i64
}

impl<'a> Default for SecretAccessor<'a> {
    fn default() -> Self {
        Self {
            dbus_name: Optional::from(None),
            uid: 0,
            pid: 0,
            timestamp: 0,
            process_name: Optional::from(None)
        }
    }
}

impl SecretAccessor<'static> {
    /// Fetch data about a SecretAccessor given a unique name
    pub async fn from_dbus_name<'a>(connection: &Connection, name: &UniqueName<'a>) -> Result<Self> {
        let prox = DBusProxy::new(connection).await?;
        // clone to be owned - we need to store this
        let name: UniqueName<'static> = name.to_owned();
        let bus_name = BusName::Unique(name.as_ref());
        // fetch pid and uid using dbus apis
        let pid = prox.get_connection_unix_process_id(bus_name.as_ref()).await.map_err(zbus::Error::from)?;
        let uid = prox.get_connection_unix_user(bus_name).await.map_err(zbus::Error::from)?;
        
        let process_name = spawn_blocking(move || {
            // fetch process info
            let mut system = System::new();
            let pid_struct = Pid::from_u32(pid);
            system.refresh_processes_specifics(
                // only fetch info about this process
                ProcessesToUpdate::Some(&[pid_struct]),
                false,
                // only fetches name/pid
                ProcessRefreshKind::nothing()
            );
            // get name
            let process = system.process(pid_struct)?;
            Some(process.name().to_string_lossy().into_owned())
        }).await.unwrap().into();
        
        Ok(Self {
            uid,
            pid,
            dbus_name: Optional::from(Some(name)),
            timestamp: Timestamp::now().as_millisecond(),
            process_name
        })
    }
}

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: Box<dyn SecretStore<'a> + Send + Sync>,
    pub last_access: Arc<RwLock<Option<SecretAccessor<'static>>>>,
}

impl<'a> Item<'a> {
    fn path(&'_ self) -> ObjectPath<'_> {
        secret_path(&*self.collection_id, &*self.id).unwrap()
    }

    async fn broadcast_collection_signal(&self, connection: &Connection, name: &str) -> Result {
        Collection::broadcast_collection_signal(
            self.store.as_ref(),
            self.collection_id.clone(),
            connection,
            name,
            self.path(),
        )
        .await
    }

    pub async fn read_with_session(
        &self,
        header: &Header<'_>,
        session: &InterfaceDeref<'_, Session>,
        connection: &Connection
    ) -> Result<Secret> {
        debug!(
            "Fetching secret {}/{} for {}",
            self.collection_id,
            self.id,
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into())
        );

        let secret_value = self
            .store
            .read_secret(&*self.collection_id, &*self.id, true)
            .await?;
        
        // update fetch access info
        let access_info = if let Some(id) = header.sender() {
            Some(SecretAccessor::from_dbus_name(connection, id).await?)
        } else {
            None
        };
        *self.last_access.write().await = access_info;

        session.encrypt(secret_value, header)
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item<'static> {
    /// Custom method for accessor info.
    /// It would probably be more spec-compliant to define a custom interface
    /// for this method but that would require a new struct with zbus.
    async fn last_access(&'_ self) -> Optional<SecretAccessor<'_>> {
        Optional::from(self.last_access.read().await.clone())
    }
    
    async fn delete(
        &'_ self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath<'_>> {
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
        #[zbus(connection)] connection: &Connection
    ) -> Result<(Secret,)> {
        Ok((self
            .read_with_session(
                &header,
                &try_interface(object_server.interface::<_, Session>(&session).await)?
                    .ok_or(Error::InvalidSession)?
                    .get()
                    .await,
                connection
            )
            .await?,))
    }

    async fn set_secret(
        &self,
        secret: Secret,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<()> {
        debug!(
            "Setting secret {}/{} from {}",
            self.collection_id,
            self.id,
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into())
        );

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
