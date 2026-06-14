use std::io::{self, Write};
use std::process::ExitCode;
use pass_secret_service::{config, key_store};

#[derive(argh::FromArgs)]
/// Setup tool for alohomora-service
struct SetupArgs {
    /// clear existing setup state and secret store files
    #[argh(switch, long = "clear")]
    clear: bool,
}

fn confirm_clear() -> bool {
    let expected = "I want to clear my secret store";
    println!("WARNING: This will permanently delete your local setup keys, device pairing state, and stored secrets!");
    print!("Please type the following sentence to confirm:\n  \"{}\"\n> ", expected);
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        if input.trim() == expected {
            return true;
        }
    }
    false
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: SetupArgs = argh::from_env();

    if args.clear {
        if !confirm_clear() {
            eprintln!("Confirmation failed. Action aborted.");
            return ExitCode::FAILURE;
        }

        match key_store::clear_secret_store().await {
            Ok(_) => {
                println!("Secret store cleared successfully.");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error clearing secret store: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    let config = match config::AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match key_store::run_setup(&config).await {
        Ok(true) => {
            let key_dir = key_store::get_key_dir();
            let local_key_path = key_dir.join(key_store::LOCAL_KEY_FILE);
            let local_key = match key_store::read_local_key(&local_key_path).await {
                Ok(Some(key)) => key,
                _ => {
                    eprintln!("Error: local key not found after setup.");
                    return ExitCode::FAILURE;
                }
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            match pass_secret_service::http_server::spawn_setup_server(config, local_key, tx).await {
                Ok(_server_handle) => {
                    println!("Waiting for Android device registration...");
                    let _ = rx.await;
                    println!("Registration successful! Setup completed successfully.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error starting registration server: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Setup error: {}", e);
            ExitCode::FAILURE
        }
    }
}
