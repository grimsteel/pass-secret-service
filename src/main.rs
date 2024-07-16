use pass::PasswordStore;
use zbus::Connection;

mod pass;
mod error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let connection = Connection::session().await?;
    //connection.request_name("org.freedesktop.secrets").await?;

    let store = PasswordStore::from_env()?;

    println!("{:?}", store.write_password("bbb/ccc/test_password", "aaaaa".as_bytes().to_owned()).await?);

    Ok(())
}
