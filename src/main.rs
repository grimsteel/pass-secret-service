use dbus_server::Service;
use pass::PasswordStore;
use zbus::Connection;

mod dbus_server;
mod error;
mod pass;
mod secret_store;
mod redb_imps;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pass = Box::leak(Box::new(PasswordStore::from_env()?));

    let connection = Connection::session().await?;

    let service = Service::init(connection.clone(), pass).await?;

    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    connection.request_name("org.freedesktop.secrets").await?;

    loop {
        std::future::pending::<()>().await;
    }
}
