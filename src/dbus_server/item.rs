use jiff::Timestamp;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::{sync::RwLock, task::spawn_blocking};

use zbus::{
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::{BusName, UniqueName},
    object_server::InterfaceDeref,
    zvariant::{ObjectPath, Optional, Type, Value},
    Connection, ObjectServer,
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
    pub timestamp: i64,
}

impl<'a> Default for SecretAccessor<'a> {
    fn default() -> Self {
        Self {
            dbus_name: Optional::from(None),
            uid: 0,
            pid: 0,
            timestamp: 0,
            process_name: Optional::from(None),
        }
    }
}

impl SecretAccessor<'static> {
    /// Fetch data about a SecretAccessor given a unique name
    pub async fn from_dbus_name<'a>(
        connection: &Connection,
        name: &UniqueName<'a>,
    ) -> Result<Self> {
        let prox = DBusProxy::new(connection).await?;
        // clone to be owned - we need to store this
        let name: UniqueName<'static> = name.to_owned();
        let bus_name = BusName::Unique(name.as_ref());
        // fetch pid and uid using dbus apis
        let pid = prox
            .get_connection_unix_process_id(bus_name.as_ref())
            .await
            .map_err(zbus::Error::from)?;
        let uid = prox
            .get_connection_unix_user(bus_name)
            .await
            .map_err(zbus::Error::from)?;

        let process_name = spawn_blocking(move || {
            // fetch process info
            let mut system = System::new();
            let pid_struct = Pid::from_u32(pid);
            system.refresh_processes_specifics(
                // only fetch info about this process
                ProcessesToUpdate::Some(&[pid_struct]),
                false,
                // only fetches name/pid
                ProcessRefreshKind::nothing(),
            );
            // get name
            let process = system.process(pid_struct)?;
            Some(process.name().to_string_lossy().into_owned())
        })
        .await
        .unwrap()
        .into();

        Ok(Self {
            uid,
            pid,
            dbus_name: Optional::from(Some(name)),
            timestamp: Timestamp::now().as_millisecond(),
            process_name,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: Box<dyn SecretStore<'a> + Send + Sync>,
    pub last_access: Arc<RwLock<Option<SecretAccessor<'static>>>>,
    pub notify_on_access: bool,
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
        connection: &Connection,
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

        // send desktop notification if enabled
        if self.notify_on_access {
            let label = self
                .store
                .get_secret_label(self.collection_id.clone(), self.id.clone())
                .await
                .unwrap_or_else(|_| self.id.to_string());
            send_access_notification(connection, &label, access_info.as_ref()).await;
        }

        *self.last_access.write().await = access_info;

        session.encrypt(secret_value, header)
    }
}

async fn send_access_notification(
    connection: &Connection,
    label: &str,
    accessor: Option<&SecretAccessor<'_>>,
) {
    let summary = format!("Secret '{}' accessed", label);
    let body = if let Some(accessor) = accessor {
        let process = accessor
            .process_name
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("<unknown>");
        format!(
            "Application <b>{}</b> (PID {}, UID {}) accessed this secret.",
            process, accessor.pid, accessor.uid
        )
    } else {
        // We don't know anything about the accessor
        "An unknown application accessed this secret".into()
    };
    let actions: Vec<&str> = vec![];
    let hints: HashMap<&str, Value<'_>> = HashMap::new();

    if let Err(e) = connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "pass-secret-service",
                0u32,
                "dialog-password",
                summary.as_str(),
                body.as_str(),
                actions,
                hints,
                -1i32,
            ),
        )
        .await
    {
        warn!("Failed to send access notification: {}", e);
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
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(Secret,)> {
        Ok((self
            .read_with_session(
                &header,
                &try_interface(object_server.interface::<_, Session>(&session).await)?
                    .ok_or(Error::InvalidSession)?
                    .get()
                    .await,
                connection,
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
    };

    use redb::{
        Database, MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition,
    };
    use tempfile::tempdir;
    use tokio::{fs, net::UnixStream, process::Command};
    use zbus::{connection::Builder, Guid};

    use super::Item;
    use crate::{
        dbus_server::utils::secret_path,
        pass::PasswordStore,
        secret_store::{redb::RedbSecretStore, RedbHashMap, SecretStore, PASS_SUBDIR},
    };

    const ATTRIBUTES_TABLE: MultimapTableDefinition<(&str, &str), &str> =
        MultimapTableDefinition::new("attributes");
    const ATTRIBUTES_TABLE_REVERSE: TableDefinition<&str, RedbHashMap<&str, &str>> =
        TableDefinition::new("attributes-reverse");
    const LABELS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("labels");

    struct GpgAgentCleanup(PathBuf);

    impl Drop for GpgAgentCleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("gpgconf")
                .arg("--homedir")
                .arg(&self.0)
                .args(["--kill", "gpg-agent"])
                .status();
        }
    }

    async fn init_gpg_home(gpg_home: &Path) -> String {
        const RECIPIENT: &str = "pass-secret-service-test@example.invalid";

        fs::create_dir(gpg_home).await.unwrap();
        fs::set_permissions(gpg_home, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let output = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gpg_home)
            .args([
                "--passphrase",
                "",
                "--quick-generate-key",
                RECIPIENT,
                "rsa2048",
                "encr",
                "0",
            ])
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create test GPG key: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        RECIPIENT.to_owned()
    }

    #[tokio::test]
    async fn item_delete_removes_all_secret_storage() {
        let temp = tempdir().unwrap();
        let gpg_home = temp.path().join("gnupg");
        let password_store_dir = temp.path().join("password-store");
        let _gpg_agent_cleanup = GpgAgentCleanup(gpg_home.clone());
        let recipient = init_gpg_home(&gpg_home).await;
        fs::create_dir(&password_store_dir).await.unwrap();
        fs::write(password_store_dir.join(".gpg-id"), recipient)
            .await
            .unwrap();

        let pass = Box::leak(Box::new(PasswordStore::for_test(
            password_store_dir.clone(),
            &gpg_home,
        )));
        let store = RedbSecretStore::new(pass).await.unwrap();
        let collection_id = Arc::new(
            store
                .create_collection(Some("test".into()), None)
                .await
                .unwrap(),
        );
        let attributes = HashMap::from([
            ("application".to_owned(), "regression-test".to_owned()),
            ("account".to_owned(), "example".to_owned()),
        ]);
        let secret_id = Arc::new(
            store
                .create_secret(
                    collection_id.clone(),
                    Some("Secret label".into()),
                    b"secret value".to_vec(),
                    Arc::new(attributes.clone()),
                )
                .await
                .unwrap(),
        );
        let secret_file = password_store_dir
            .join(PASS_SUBDIR)
            .join(&*collection_id)
            .join(format!("{secret_id}.gpg"));

        assert!(secret_file.exists());
        assert_eq!(
            store
                .get_secret_label(collection_id.clone(), secret_id.clone())
                .await
                .unwrap(),
            "Secret label"
        );
        assert_eq!(
            store
                .read_secret_attrs(collection_id.clone(), secret_id.clone())
                .await
                .unwrap(),
            attributes
        );
        for (key, value) in &attributes {
            let matching_ids = store
                .search_collection(
                    collection_id.clone(),
                    Arc::new(HashMap::from([(key.clone(), value.clone())])),
                )
                .await
                .unwrap();
            assert!(matching_ids.contains(secret_id.as_ref()));
        }

        let guid = Guid::generate();
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let (client, server) = futures_util::try_join!(
            Builder::unix_stream(client_stream).p2p().build(),
            Builder::unix_stream(server_stream)
                .server(guid)
                .unwrap()
                .p2p()
                .build(),
        )
        .unwrap();
        let item_path = secret_path(&*collection_id, &*secret_id).unwrap();
        let item = Item {
            collection_id: collection_id.clone(),
            id: secret_id.clone(),
            store: Box::new(store.clone()),
            last_access: Default::default(),
            notify_on_access: false,
        };
        server
            .object_server()
            .at(&item_path, item.clone())
            .await
            .unwrap();

        // Calling the interface implementation directly avoids requiring a session bus while
        // exercising the same public Item.Delete handler with real zbus dependencies.
        item.delete(&server, &server.object_server()).await.unwrap();

        assert!(!secret_file.exists());
        assert!(store
            .search_collection(collection_id.clone(), Arc::new(attributes.clone()))
            .await
            .unwrap()
            .is_empty());

        drop(item);
        drop(store);
        drop(server);
        drop(client);

        let attributes_db = password_store_dir
            .join(PASS_SUBDIR)
            .join(&*collection_id)
            .join("attributes.redb");
        let db = Database::open(attributes_db).unwrap();
        let tx = db.begin_read().unwrap();
        let labels = tx.open_table(LABELS_TABLE).unwrap();
        let attributes_reverse = tx.open_table(ATTRIBUTES_TABLE_REVERSE).unwrap();
        let attributes_table = tx.open_multimap_table(ATTRIBUTES_TABLE).unwrap();

        assert!(ReadableTable::get(&labels, secret_id.as_str())
            .unwrap()
            .is_none());
        assert!(ReadableTable::get(&attributes_reverse, secret_id.as_str())
            .unwrap()
            .is_none());
        for (key, value) in &attributes {
            assert!(
                !ReadableMultimapTable::get(&attributes_table, (key.as_str(), value.as_str()),)
                    .unwrap()
                    .map(|entry| entry.unwrap().value() == secret_id.as_str())
                    .any(|matches| matches)
            );
        }
    }
}
