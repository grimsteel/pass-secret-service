use cli::CliArgs;
use dbus_server::service::Service;
use pass::PasswordStore;
use zbus::Connection;

mod cli;
mod dbus_server;
mod error;
mod pass;
mod redb_imps;
mod secret_store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: CliArgs = argh::from_env();

    if args.print_version {
        // print the current crate version and exit
        eprintln!("pass-secret-service v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let pass = Box::leak(Box::new(PasswordStore::from_env(args.password_store_dir.map(|d| d.into()))?));

    let connection = Connection::session().await?;

    eprintln!("D-Bus session connection established.");

    let service = Service::init(connection.clone(), pass, args.forget_password_on_lock).await?;

    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    connection.request_name("org.freedesktop.secrets").await?;

    eprintln!("Acquired `org.freedesktop.secrets` name.");

    loop {
        std::future::pending::<()>().await;
    }
}
