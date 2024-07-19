use std::{
    fmt::Display,
    io::{self, ErrorKind},
};

use zbus::{
    fdo,
    message::{self, Header},
    names::ErrorName,
    DBusError, Message,
};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    DbusError(zbus::Error),
    RedbError(redb::Error),
    GpgError(String),
    // pass is not initialized
    NotInitialized,
    InvalidSession,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<zbus::Error> for Error {
    fn from(value: zbus::Error) -> Self {
        Self::DbusError(value)
    }
}

impl From<redb::Error> for Error {
    fn from(value: redb::Error) -> Self {
        Self::RedbError(value)
    }
}

impl DBusError for Error {
    fn create_reply(&self, msg: &Header<'_>) -> zbus::Result<Message> {
        let name = self.name();
        #[allow(deprecated)]
        let msg = message::Builder::error(msg, name)?;

        match self {
            Error::IoError(e) => msg.build(&(e.to_string(),)),
            Error::DbusError(e) => msg.build(&(e.to_string(),)),
            Error::RedbError(e) => msg.build(&(e.to_string(),)),
            Error::GpgError(e) => msg.build(&(e,)),
            _ => msg.build(&()),
        }
    }

    fn name(&self) -> ErrorName<'_> {
        ErrorName::from_static_str_unchecked(match self {
            Error::IoError(e) if e.kind() == ErrorKind::NotFound => {
                "org.freedesktop.Secret.Error.NoSuchObject"
            }
            Error::IoError(_) => "org.freedesktop.DBus.Error.IOError",
            Error::DbusError(_) => "org.freedesktop.zbus.Error",
            Error::RedbError(_) => "me.grimsteel.PassSecretService.ReDBError",
            Error::GpgError(_) => "me.grimsteel.PassSecretService.GPGError",
            Error::NotInitialized => "me.grimsteel.PassSecretService.PassNotInitialized",
            Error::InvalidSession => "org.freedesktop.Secret.Error.NoSession",
        })
    }

    fn description(&self) -> Option<&str> {
        match self {
            Error::IoError(_) => None,
            Error::DbusError(zbus::Error::MethodError(_, desc, _)) => desc.as_deref(),
            Error::DbusError(_) => None,
            Error::RedbError(_) => None,
            Error::GpgError(e) => Some(e.as_str()),
            Error::NotInitialized => None,
            Error::InvalidSession => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "I/O Error: {e}"),
            Error::DbusError(e) => write!(f, "D-Bus Error: {e}"),
            Error::GpgError(e) => write!(f, "GPG Error; {e}"),
            Error::RedbError(e) => write!(f, "ReDB Error: {e}"),
            Error::NotInitialized => write!(f, "Pass is not initialized"),
            Error::InvalidSession => write!(f, "Invalid secret service session"),
        }
    }
}

impl From<Error> for fdo::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::IoError(err) => Self::IOError(format!("{err}")),
            Error::DbusError(err) => Self::ZBus(err),
            err => Self::Failed(format!("{err}")),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub trait IntoResult<T> {
    fn into_result(self) -> Result<T>;
}

impl<T, E: Into<redb::Error>> IntoResult<T> for std::result::Result<T, E> {
    fn into_result(self) -> Result<T> {
        self.map_err(|e| Into::<redb::Error>::into(e).into())
    }
}

pub trait OptionNoneNotFound<T> {
    fn into_not_found(self) -> Result<T>;
}

impl<T> OptionNoneNotFound<T> for Option<T> {
    fn into_not_found(self) -> Result<T> {
        self.ok_or(io::Error::from(io::ErrorKind::NotFound).into())
    }
}

macro_rules! ignore_nonexistent_table {
    ($expression:expr) => {
        match $expression {
            Ok(t) => t,
            // table does not exist yet - that's ok
            Err(redb::TableError::TableDoesNotExist(_)) => return Err(io::Error::from(io::ErrorKind::NotFound).into()),
            Err(e) => return Err(e).into_result(),
        }
    };
}
pub(crate) use ignore_nonexistent_table;
