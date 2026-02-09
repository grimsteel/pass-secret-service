use argh::FromArgs;

#[derive(FromArgs)]
/// Background daemon for pass-secret-service: An implementation of org.freedesktop.secrets using pass
pub struct CliArgs {
    /// location of the password store. Will fall back to $PASSWORD_STORE_DIR, or $HOME/.password-store if not set.
    #[argh(option, long = "path", short = 'd')]
    pub password_store_dir: Option<String>,

    /// make gpg-agent forget the cached key password when any collection is locked
    #[argh(switch, short = 'f')]
    pub forget_password_on_lock: bool,

    /// print the current version
    #[argh(switch, short = 'V', long = "version")]
    pub print_version: bool,

    /// log level (overridden by $RUST_LOG environment variable)
    /// uses env_logger syntax
    #[argh(option)]
    pub log_level: Option<String>,
    
    /// optional subcommand
    #[argh(subcommand)]
    pub subcommand: Option<CliSubcommand>
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum CliSubcommand {
    RunService(RunServiceSubcommand),
    LastAccessor(LastAccessorSubcommand)
}

#[derive(FromArgs)]
#[argh(subcommand, name = "run-service")]
/// Run the secret-service provider
pub struct RunServiceSubcommand {}


#[derive(FromArgs)]
#[argh(subcommand, name = "last-accessor")]
/// Retrieve the last application to access the specified secret
pub struct LastAccessorSubcommand {
    /// the collection of the secret. Takes precedence over --alias
    #[argh(option, short = 'C', long = "collection")]
    pub collection: Option<String>,
    
    /// the collection alias of the secret. `default` if neither this nor --collection is given.
    #[argh(option, short = 'A', long = "alias")]
    pub alias: Option<String>,
    
    /// the secret ID. use `secret-tool search` to find
    #[argh(positional)]
    pub id: String
}
