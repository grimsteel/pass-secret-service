use std::{fmt::Display, io};

use redb::TableError;
use zbus::fdo;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    DbusError(zbus::Error),
    RedbError(redb::Error),
    GpgError(String),
    // pass is not initialized
    NotInitialized,
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

impl From<Error> for fdo::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::IoError(err) => Self::IOError(format!("{err}")),
            Error::DbusError(err) => Self::ZBus(err),
            err => Self::Failed(format!("{err}")),
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

macro_rules! ignore_nonexistent_table {
    ($expression:expr, $default:expr) => {
        match $expression {
            Ok(t) => t,
            // table does not exist yet - that's ok
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok($default),
            Err(e) => return Err(e.into()),
        }
    }
}
pub(crate) use ignore_nonexistent_table;
