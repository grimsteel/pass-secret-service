use std::env;

use crate::error::{Error, Result};

const DEFAULT_DOMAIN: &str = "lukegt.com";
const DEFAULT_PORT: u16 = 19969;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub domain: String,
    pub external_port: u16,
    pub internal_port: u16,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let domain = env::var("ALOHOMORA_DOMAIN").unwrap_or_else(|_| DEFAULT_DOMAIN.into());
        let external_port = read_port_env("ALOHOMORA_EXTERNAL_PORT")?;
        let internal_port = read_port_env("ALOHOMORA_INTERNAL_PORT")?;

        Ok(Self {
            domain,
            external_port,
            internal_port,
        })
    }
}

fn read_port_env(name: &str) -> Result<u16> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| Error::ConfigError(format!("{name} must be a valid u16, got `{value}`"))),
        Err(_) => Ok(DEFAULT_PORT),
    }
}
