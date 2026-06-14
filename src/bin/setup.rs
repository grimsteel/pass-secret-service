use std::process::ExitCode;
use pass_secret_service::{config, key_store};

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = match config::AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match key_store::run_setup(&config).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Setup error: {}", e);
            ExitCode::FAILURE
        }
    }
}
