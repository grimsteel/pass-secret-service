use std::fmt::{Debug, Display};

use zbus::zvariant::{DeserializeDict, ObjectPath, OwnedObjectPath, SerializeDict, Type};

pub const EMPTY_PATH: ObjectPath = ObjectPath::from_static_str_unchecked("/");

pub fn collection_path<'a, 'b, T: Display + Debug>(collection_id: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}"
    ))
    .ok()
}
pub fn secret_path<'a, 'b, T: Display + Debug>(
    collection_id: T,
    secret_id: T,
) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{collection_id}/{secret_id}"
    ))
    .ok()
}
pub fn secret_alias_path<'a, 'b, T: Display + Debug>(
    alias: T,
    secret_id: T,
) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!(
        "/org/freedesktop/secrets/aliases/{alias}/{secret_id}"
    ))
    .ok()
}
pub fn alias_path<'a, 'b, T: Display>(alias: T) -> Option<ObjectPath<'b>> {
    ObjectPath::try_from(format!("/org/freedesktop/secrets/aliases/{alias}")).ok()
}
pub fn try_interface<T>(result: zbus::Result<T>) -> zbus::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(zbus::Error::InterfaceNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct Secret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}