use std::{fmt::Display, io};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    DbusError(zbus::Error),
    GpgError(String),
    // pass is not initialized
    NotInitialized
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

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "I/O Error: {e}"),
            Error::DbusError(e) => write!(f, "D-Bus Error: {e}"),
            Error::GpgError(e) => write!(f, "GPG Error; {e}"),
            Error::NotInitialized => write!(f, "Pass is not initialized"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T=()> = std::result::Result<T, Error>;
