use futures_util::StreamExt;
use tokio::{
    select,
    sync::oneshot::{self, Sender},
    task,
};
use zbus::{
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::OwnedUniqueName,
    zvariant::OwnedObjectPath,
    Connection, ObjectServer,
};

use crate::error::{Error, Result};

use super::secret_transfer::{Secret, SessionTransfer};
use super::utils::try_interface;

pub struct Session {
    transfer: Box<dyn SessionTransfer + Send + Sync>,
    client_name: OwnedUniqueName,
    path: OwnedObjectPath,
    closed: Option<Sender<()>>,
}
impl Session {
    pub fn new(
        transfer: Box<dyn SessionTransfer + Send + Sync>,
        client_name: OwnedUniqueName,
        path: OwnedObjectPath,
        connection: Connection,
    ) -> Self {
        let (tx, rx) = oneshot::channel();

        let name_str = client_name.to_string();
        let path_2 = path.clone();
        task::spawn(async move {
            let dbus = DBusProxy::new(&connection).await?;

            let object_server = connection.object_server();

            let mut name_gone_stream = dbus
                .receive_name_owner_changed_with_args(&[(0, &name_str), (2, "")])
                .await?;

            select! {
                _ = rx => {
                    // already removed
                },
                _ = name_gone_stream.next() => {
                    // need to remove
                    object_server.remove::<Self, _>(&path_2).await?;
                }
            }

            zbus::Result::Ok(())
        });

        Self {
            transfer,
            client_name,
            path,
            closed: Some(tx),
        }
    }

    pub fn decrypt(&self, secret: Secret, header: &Header<'_>) -> Result<Vec<u8>> {
        // make sure they're allowed to do this
        if !header.sender().is_some_and(|s| self.client_name == *s) {
            return Err(Error::PermissionDenied);
        }

        self.transfer.decrypt(secret)
    }

    pub fn encrypt(&self, secret: Vec<u8>, header: &Header<'_>) -> Result<Secret> {
        // make sure they're allowed to do this
        if !header.sender().is_some_and(|s| self.client_name == *s) {
            return Err(Error::PermissionDenied);
        }

        self.transfer.encrypt(secret, self.path.clone())
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        // make sure they're allowed to do this
        if header.sender().is_some_and(|n| self.client_name == *n) {
            try_interface(object_server.remove::<Self, _>(&self.path).await)?;

            if let Some(tx) = self.closed.take() {
                let _ = tx.send(());
            }

            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "You didn't create that session".into(),
            ))
        }
    }
}
