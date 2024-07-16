use std::{borrow::Cow, collections::HashMap, env, path::{Path, PathBuf}, process::Stdio};
use tokio::{fs::read, io::AsyncWriteExt, process::Command};

use crate::error::{Error, Result};

pub struct PasswordStore {
    directory: PathBuf,
    gpg_opts: Option<String>,
    umask: u32
}

impl PasswordStore {
    /// Initialize this PasswordStore instance from env vars
    pub fn from_env() -> Result<Self> {
        let mut env: HashMap<String, String> = env::vars().collect();

        // Either ~/.password-store or $PASSWORD_STORE_DIR
        let directory = env.get("PASSWORD_STORE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = Path::new(env.get("HOME").expect("$HOME must be set"));
                home.join(".password-store")
            });

        let gpg_opts = env.remove("PASSWORD_STORE_GPG_OPTS");

        let umask = env.get("PASSWORD_STORE_UMASK")
            .and_then(|s| u32::from_str_radix(s, 8).ok())
            .unwrap_or(0o077);
        
        Ok(Self {
            directory,
            gpg_opts,
            umask
        })
    }

    fn get_full_secret_path(&self, path: impl AsRef<Path>) -> PathBuf {
        let mut path = self.directory.join(path);

        // add .gpg to the end if necessary
        if !path.ends_with(".gpg"){
            let os_str = path.as_mut_os_string();
            os_str.push(".gpg");
        };

        path
    }

    /// Read a single password at the given path
    pub async fn read_password(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let contents = read(self.get_full_secret_path(path)).await?;

        let mut process = Command::new("gpg")
            .arg("--decrypt")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdin = process.stdin.take().expect("child has stdin");

        tokio::task::spawn(async move {
            stdin.write_all(&contents).await
        });
        
        let output = process.wait_with_output().await?;
        if output.status.success() {
            // gpg decrypted successfulyl
            Ok(output.stdout)
        } else {
            Err(Error::GpgError(String::from_utf8_lossy(&output.stderr).into_owned()))
        }
    }

    /// write a single password
    pub async fn write_password(&self, path: impl AsRef<Path>, value: &[u8]) -> Result<()> {
        
    }
}
