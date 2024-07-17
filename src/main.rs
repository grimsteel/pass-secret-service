use dbus_server::init_service;
use pass::PasswordStore;
use zbus::Connection;

mod dbus_server;
mod error;
mod pass;
mod secret_store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::session().await?;

    let service = init_service(connection.clone()).await?;

    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    connection.request_name("org.freedesktop.secrets").await?;

    loop {
        std::future::pending::<()>().await;
    }
}
