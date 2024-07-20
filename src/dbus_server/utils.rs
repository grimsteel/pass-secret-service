use std::{fmt::Display, io, time::SystemTime};

use zbus::zvariant::{DeserializeDict, ObjectPath, OwnedObjectPath, SerializeDict, Type};

pub const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

pub fn collection_path<T: Display>(collection_id: T) -> Option<ObjectPath<'static>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}"
    ))
    .ok()
}
pub fn secret_path<T: Display>(collection_id: T, secret_id: T) -> Option<ObjectPath<'static>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}/{secret_id}"
    ))
    .ok()
}
pub fn secret_alias_path<T: Display>(alias: T, secret_id: T) -> Option<ObjectPath<'static>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/aliases/{alias}/{secret_id}"
    ))
    .ok()
}
pub fn alias_path<T: Display>(alias: T) -> Option<ObjectPath<'static>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/aliases/{alias}")).ok()
}
pub fn session_path<T: Display>(session_id: T) -> Option<ObjectPath<'static>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/session/{session_id}")).ok()
}
pub fn try_interface<T>(result: zbus::Result<T>) -> zbus::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(zbus::Error::InterfaceNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn time_to_int(time: io::Result<SystemTime>) -> u64 {
    time.ok()
        // return 0 for times before the epoch or for platforms where this isn't supported
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|t| t.as_secs())
        .unwrap_or_default()
}

#[derive(DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub content_type: Option<String>,
}
