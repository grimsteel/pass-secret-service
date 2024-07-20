use zbus::{
    fdo, interface, message::Header, names::OwnedUniqueName, zvariant::OwnedObjectPath,
    ObjectServer,
};

use crate::error::{Error, Result};

use super::utils::{try_interface, Secret};

pub enum SessionAlgorithm {
    Plain,
}

pub struct Session {
    pub alg: SessionAlgorithm,
    pub client_name: OwnedUniqueName,
    pub path: OwnedObjectPath,
}
impl Session {
    pub fn decrypt(&self, secret: Secret, header: Header<'_>) -> Result<Vec<u8>> {
        // make sure they're allowed to do this
        if !header.sender().is_some_and(|s| self.client_name == *s) {
            return Err(Error::PermissionDenied);
        }

        match self.alg {
            SessionAlgorithm::Plain => Ok(secret.value),
        }
    }

    pub fn encrypt(&self, secret: Vec<u8>, header: Header<'_>) -> Result<Secret> {
        // make sure they're allowed to do this
        if !header.sender().is_some_and(|s| self.client_name == *s) {
            return Err(Error::PermissionDenied);
        }

        match self.alg {
            SessionAlgorithm::Plain => Ok(Secret {
                session: self.path.clone(),
                parameters: Some(vec![]),
                value: secret,
                content_type: Some("".into()),
            }),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        // make sure they're allowed to do this
        if header.sender().is_some_and(|n| self.client_name == *n) {
            try_interface(object_server.remove::<Self, _>(&self.path).await)?;
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "You didn't create that session".into(),
            ))
        }
    }
}
