use std::process::ExitCode;

use cli::CliArgs;
use dbus_server::service::Service;
use env_logger::Env;
use jiff::{SignedDuration, Timestamp, Zoned, fmt::{friendly::SpanPrinter, rfc2822}, tz::TimeZone};
use log::{debug, error, info};
use pass::PasswordStore;
use zbus::{Connection, zvariant::Optional};

use crate::{cli::{CliSubcommand, LastAccessorSubcommand}, dbus_server::{SecretAccessor, service::DEFAULT_COLLECTION_NAME}, error::Result};

mod cli;
mod dbus_server;
mod error;
mod pass;
mod secret_store;

// Constants from the spec
const WELL_KNOWN_NAME: &'static str = "org.freedesktop.secrets";
const BASE_PATH: &'static str = "/org/freedesktop/secrets";

async fn run(args: CliArgs) -> Result {
    match args.subcommand {
        None | Some(CliSubcommand::RunService(_)) => {
            // None = no subcommand given. Default is to run service
            
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
                .at(BASE_PATH, service)
                .await?;
        
            connection.request_name(WELL_KNOWN_NAME).await?;
        
            info!("Acquired well-known name: `{}`", WELL_KNOWN_NAME);
        
            loop {
                std::future::pending::<()>().await;
            }
        },
        Some(CliSubcommand::LastAccessor(LastAccessorSubcommand { collection, id, alias })) => {
            let connection = Connection::session().await?;
            
            // debug because this isn't really relevant for just fetching info
            debug!(
                "D-Bus session connection established. Unique name: {}",
                connection.unique_name().map(|s| s.as_str()).unwrap_or("?")
            );
            
            // collection takes precedence, default _alias_ used if neither provided
            let collection_specifier_type = if collection.is_some() {
                "collection"
            } else {
                "aliases"
            };
            
            // collection takes precendence over alias
            let collection_alias_name = collection
                .or(alias)
                .unwrap_or_else(|| DEFAULT_COLLECTION_NAME.into());
            
            let secret_path = format!("{collection_specifier_type}/{collection_alias_name}/{id}");
            // call last_access
            let call_result = connection
                .call_method(Some(WELL_KNOWN_NAME), format!("{BASE_PATH}/{secret_path}"), Some("org.freedesktop.Secret.Item"), "LastAccess", &())
                .await;
            let method_body = match call_result {
                Ok(m) => m,
                // print friendly error mesasage for unknown objecdt
                Err(zbus::Error::MethodError(e, _, _)) if e == "org.freedesktop.DBus.Error.UnknownObject" => {
                    error!("No secret found at {secret_path}");
                    return Ok(());
                }
                Err(e) => {
                    return Err(dbg!(e).into());
                }
            };
            let body = method_body.body();
            let accessor: Option<SecretAccessor> = body.deserialize::<Optional<SecretAccessor>>()?.into();
            
            match accessor {
                None => {
                    info!("No programs have accessed {secret_path} since the service started.")
                },
                Some(SecretAccessor { uid, pid, process_name, timestamp, .. }) => {
                    // create a zoned struct for formatting
                    let orig = Zoned::new(Timestamp::from_millisecond(timestamp).unwrap(), TimeZone::system());
                    let diff = SignedDuration::from_millis(timestamp - Timestamp::now().as_millisecond());
                    info!("The last access of {secret_path} was {}:", SpanPrinter::new().duration_to_string(&diff));
                    info!("  User: {uid}");
                    info!("  Program: {} (PID {pid})", process_name.as_ref().map(|s| &s[..]).unwrap_or_else(|| "<unknown>"));
                    info!("  Timestamp: {}", rfc2822::to_string(&orig).unwrap());
                }
            };            
            
            Ok(())
        }
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
