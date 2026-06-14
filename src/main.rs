use std::process::ExitCode;
use pass_secret_service::{cli, run};

#[tokio::main]
async fn main() -> ExitCode {
    let args: cli::CliArgs = argh::from_env();

    // if the environment variable isn't set, fallback to the cli arg, and use info if that isn't set
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.as_deref().unwrap_or("info")),
    )
    .init();

    if args.print_version {
        // print the current crate version and exit
        log::info!("pass-secret-service v{}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    // handle any startup errors cleanly
    if let Err(err) = run(args).await {
        log::error!("{}", err);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
