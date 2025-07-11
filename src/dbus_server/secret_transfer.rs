use serde::{Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};

use crate::error::Result;

/// An encrypted secret
#[derive(Type, Debug, Deserialize, Serialize, PartialEq)]
pub struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// Common trait for all methods for transferring secrets
pub trait SessionTransfer {
    fn decrypt(&self, secret: Secret) -> Result<Vec<u8>>;
    fn encrypt(&self, value: Vec<u8>, session: OwnedObjectPath) -> Result<Secret>;
}

/// Plain-text transfer
pub struct PlainTextTransfer;
impl SessionTransfer for PlainTextTransfer {
    // passthrough

    fn decrypt(&self, secret: Secret) -> Result<Vec<u8>> {
        Ok(secret.value)
    }

    fn encrypt(&self, value: Vec<u8>, session: OwnedObjectPath) -> Result<Secret> {
        Ok(Secret {
            session,
            parameters: Vec::new(),
            value,
            content_type: "text/plain".to_string(),
        })
    }
}
