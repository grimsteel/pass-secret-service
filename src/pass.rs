use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{FileType, Metadata},
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{
    fs::{
        metadata, read, read_dir, read_to_string, remove_dir_all, remove_file, DirBuilder, File,
        OpenOptions,
    },
    io::AsyncWriteExt,
    process::Command,
};

use crate::error::{Error, Result};

#[derive(Debug)]
pub struct PasswordStore {
    pub directory: PathBuf,
    gpg_opts: Option<String>,
    file_mode: u32,
    dir_mode: u32,
}

impl PasswordStore {
    /// Initialize this PasswordStore instance from env vars
    pub fn from_env(password_store_dir: Option<PathBuf>) -> Result<Self> {
        let mut env: HashMap<String, String> = env::vars().collect();

        // Either ~/.password-store or $PASSWORD_STORE_DIR
        let directory = password_store_dir.unwrap_or_else(|| {
            env.get("PASSWORD_STORE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = Path::new(env.get("HOME").expect("$HOME must be set"));
                    home.join(".password-store")
                })
        });

        let gpg_opts = env.remove("PASSWORD_STORE_GPG_OPTS");

        let umask = env
            .get("PASSWORD_STORE_UMASK")
            .and_then(|s| u32::from_str_radix(s, 8).ok())
            .unwrap_or(0o077);

        // lower 3 octal digits
        let dir_mode = !umask & 0o777;
        // lower 3 digits without execute bit
        let file_mode = !(umask | 0o111) & 0o777;

        Ok(Self {
            directory,
            gpg_opts,
            dir_mode,
            file_mode,
        })
    }
    
    pub fn get_full_filepath(&self, path: impl AsRef<Path>, extension: &str) -> PathBuf {
        let mut path = self.directory.join(path);
        if path.extension().and_then(|s| s.to_str()).is_none_or(|s| s != extension) {
            path.add_extension(extension);
        }

        path
    }
    fn get_full_secret_path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.get_full_filepath(path, "gpg")
    }

    fn make_gpg_process(&self) -> Command {
        let mut command = Command::new("gpg");

        // apply the gpg opts
        if let Some(opts) = &self.gpg_opts {
            command.args(opts.split_ascii_whitespace());
        }

        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        command
    }

    /// Read a single password at the given path
    pub async fn read_password(&self, path: impl AsRef<Path>, can_prompt: bool) -> Result<Vec<u8>> {
        let contents = read(self.get_full_secret_path(path)).await?;

        let mut command = self.make_gpg_process();

        if !can_prompt {
            // don't activate pinentry if we can't prompt
            command.arg("--pinentry-mode=error");
        }

        command.arg("--decrypt").arg("-");

        let mut process = command.spawn()?;

        let mut stdin = process.stdin.take().expect("child has stdin");

        tokio::task::spawn(async move { stdin.write_all(&contents).await });

        let output = process.wait_with_output().await?;
        if output.status.success() {
            // gpg decrypted successfully
            Ok(output.stdout)
        } else {
            Err(Error::GpgError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    }

    /// Look for a `.gpg-id` file starting from `dir` up to `self.directory`.
    ///
    /// Some tools, like `gopass` may encrypt a file for multiple recipients and thus contain
    /// multiple IDs in the `.gpg-id` file.
    async fn get_gpg_ids(&self, dir: impl AsRef<Path>) -> Result<Vec<String>> {
        for component in dir.as_ref().ancestors() {
            let gpg_id_path = component.join(".gpg-id");
            match read_to_string(gpg_id_path).await {
                Ok(value) => return Ok(value.trim().lines().map(String::from).collect()),
                // not found, continue
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => Err(e)?,
            }

            // at the root pass dir
            if component == self.directory {
                break;
            }
        }
        // we couldn't find a gpg key
        return Err(Error::NotInitialized);
    }

    async fn ensure_dirs(&self, dir: impl AsRef<Path>) -> Result {
        // create this dir
        Ok(DirBuilder::new()
            .recursive(true)
            .mode(self.dir_mode)
            .create(dir)
            .await?)
    }

    /// write a single password
    pub async fn write_password(&self, path: impl AsRef<Path>, value: Vec<u8>) -> Result {
        let full_path = self.get_full_secret_path(path);

        let dir = full_path.parent().expect("path is a file");

        self.ensure_dirs(dir).await?;

        let gpg_ids = self.get_gpg_ids(dir).await?;

        let mut process = self
            .make_gpg_process()
            .arg("--encrypt")
            .args(
                gpg_ids
                    .into_iter()
                    .map(|recipient| format!("--recipient={recipient}")),
            )
            .arg("-")
            .spawn()?;

        let mut stdin = process.stdin.take().expect("child has stdin");

        tokio::task::spawn(async move { stdin.write_all(&value).await });

        let output = process.wait_with_output().await?;
        if output.status.success() {
            // encryption successful

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(self.file_mode)
                .open(full_path)
                .await?;

            file.write_all(&output.stdout).await?;

            Ok(())
        } else {
            Err(Error::GpgError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    }

    pub async fn delete_password(&self, path: impl AsRef<Path>) -> Result {
        let full_path = self.get_full_secret_path(path);
        match remove_file(full_path).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /****** Some useful FS utilities ******/

    /// list the file and directories inside a parent directory
    pub async fn list_items(&self, dir: impl AsRef<Path>) -> Result<Vec<(FileType, String)>> {
        let dir = self.directory.join(dir);
        self.ensure_dirs(&dir).await?;

        let mut dir_items = read_dir(dir).await?;

        let mut items = vec![];

        while let Some(item) = dir_items.next_entry().await? {
            let file_type = item.file_type().await?;
            let name = item.file_name().to_string_lossy().into_owned();
            items.push((file_type, name));
        }

        Ok(items)
    }

    /// open a file for writing
    pub async fn open_file(&self, file_path: impl AsRef<Path>) -> Result<File> {
        let path = self.directory.join(file_path);
        self.ensure_dirs(path.parent().expect("path is not a file"))
            .await?;

        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .mode(self.file_mode)
            .open(path)
            .await?)
    }

    /// get metadata on a file
    pub async fn stat_file(&self, file_path: impl AsRef<Path>) -> Result<Metadata> {
        let path = self.directory.join(file_path);
        self.ensure_dirs(path.parent().expect("path is not a file"))
            .await?;

        Ok(metadata(path).await?)
    }

    /// make a dir and all its parents
    pub async fn make_dir(&self, dir: impl AsRef<Path>) -> Result {
        self.ensure_dirs(self.directory.join(dir)).await
    }

    /// recursively remove a dir
    pub async fn remove_dir(&self, dir: impl AsRef<Path>) -> Result {
        Ok(remove_dir_all(self.directory.join(dir)).await?)
    }

    /// make gpg-agent forget the cached password for the keys associated with the given collections
    pub async fn gpg_forget_cached_password(
        &self,
        collection_dirs: HashSet<impl AsRef<Path>>,
    ) -> Result {
        // all unique GPG key ids to clear cache for
        let mut gpg_ids = HashSet::new();

        for dir in collection_dirs {
            gpg_ids.extend(self.get_gpg_ids(self.directory.join(dir)).await?);
        }

        // get the keygrip for each key
        let gpg_result = self
            .make_gpg_process()
            .arg("--batch")
            .arg("--with-colons")
            .arg("--with-keygrip")
            .arg("--list-key")
            .args(gpg_ids)
            .output()
            .await?;

        // return any errors that occurred
        if !gpg_result.status.success() {
            return Err(Error::GpgError(
                String::from_utf8_lossy(&gpg_result.stderr).into_owned(),
            ));
        }

        let gpg_out =
            String::from_utf8(gpg_result.stdout).expect("gpg colon output is valid UTF-8");

        let mut gpg_line_iter = gpg_out.trim().lines().map(|line| line.split(':'));

        loop {
            // find the (sub)key for encryption
            if gpg_line_iter
                .position(|mut line| {
                    // Field 1: type (index 0)
                    let Some(key_type) = line.nth(0) else {
                        return false;
                    };

                    // public key or subkey
                    if key_type != "pub" && key_type != "sub" {
                        return false;
                    }

                    // Field 12: capabilities (index 11, 10 after type is consumed)
                    let Some(caps) = line.nth(10) else {
                        return false;
                    };

                    // pubkey or subkey that has the 'e' (encryption) capability
                    caps.contains('e')
                })
                .is_none()
            {
                // no more keys with encryption capability found - break
                break;
            }

            // look for the following keygrip
            let Some(keygrip) = gpg_line_iter.find_map(|mut line| {
                let Some(item_type) = line.nth(0) else {
                    return None;
                };

                // keygrip
                if item_type != "grp" {
                    return None;
                }

                // Field 10: keygrip (user id) (index 9, 8 after type is consumed)
                let Some(keygrip) = line.nth(8) else {
                    return None;
                };

                Some(keygrip)
            }) else {
                return Err(Error::GpgError("no keygrip found".into()));
            };

            // make gpg agent forget the passphrase for this key
            let gpg_agent_command = format!("clear_passphrase --mode=normal {}", keygrip);
            let gpg_agent_result = Command::new("gpg-connect-agent")
                .arg(gpg_agent_command)
                .arg("/bye")
                .output()
                .await?;

            if !gpg_agent_result.status.success() {
                return Err(Error::GpgError(
                    String::from_utf8_lossy(&gpg_agent_result.stderr).into_owned(),
                ));
            }
        }

        Ok(())
    }
}
