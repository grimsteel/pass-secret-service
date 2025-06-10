use argh::FromArgs;

#[derive(FromArgs)]
/// Background daemon for pass-secret-service: An implementation of org.freedesktop.secrets using pass
pub struct CliArgs {
    /// location of the password store. Will fall back to $PASSWORD_STORE_DIR, or $HOME/.password-store if not set.
    #[argh(option, long="path", short='d')]
    pub password_store_dir: Option<String>,

    /// make gpg-agent forget the cached key password when any collection is locked
    #[argh(switch, short='f')]
    pub forget_password_on_lock: bool,

    /// print the current version
    #[argh(switch, short='V', long="version")]
    pub print_version: bool,
}
