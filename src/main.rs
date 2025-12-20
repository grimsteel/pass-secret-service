use std::process::ExitCode;

use cli::CliArgs;
use dbus_server::service::Service;
use env_logger::Env;
use log::{error, info};
use pass::PasswordStore;
use zbus::Connection;

use crate::error::Result;

mod cli;
mod dbus_server;
mod error;
mod pass;
mod secret_store;

async fn run(args: CliArgs) -> Result {
    let pass = Box::leak(Box::new(PasswordStore::from_env(
        args.password_store_dir.map(|d| d.into()),
    )?));

    let connection = Connection::session().await?;

    info!(
        "D-Bus session connection established. Unique name: {}",
        connection.unique_name().map(|s| s.as_str()).unwrap_or("?")
    );

    let service = Service::init(connection.clone(), pass, args.forget_password_on_lock).await?;

    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    connection.request_name("org.freedesktop.secrets").await?;

    info!("Acquired well-known name: `org.freedesktop.secrets`");

    loop {
        std::future::pending::<()>().await;
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: CliArgs = argh::from_env();

    // if the environment variable isn't set, fallback to the cli arg, and use info if that isn't set
    env_logger::Builder::from_env(
        Env::default().default_filter_or(args.log_level.as_deref().unwrap_or("info")),
    )
    .init();

    if args.print_version {
        // print the current crate version and exit
        info!("pass-secret-service v{}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    // handle any startup errors cleanly
    if let Err(err) = run(args).await {
        error!("{}", err);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
