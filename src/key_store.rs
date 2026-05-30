use std::{os::unix::fs::PermissionsExt, path::Path};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use tokio::{
    fs::{create_dir_all, metadata, read, read_dir, set_permissions, OpenOptions},
    io::{self, AsyncWriteExt},
};

use crate::error::{Error, Result};

const KEY_DIR: &str = "/var/lib/alohomora-service";
const LOCAL_KEY_FILE: &str = "local_key.bin";
const DEVICE_KEYS_DIR: &str = "device-keys";
const TEMP_PAIRING_KEYS_DIR: &str = "temp-pairing-keys";
const ENC_SECRET_KEY_FILE: &str = "enc_secret_key.bin";
const AES256_KEY_BYTES: usize = 32;
const AES_GCM_NONCE_BYTES: usize = 12;
const ENCRYPTED_BLOB_MAGIC: &[u8] = b"alohomora-aes256-gcm-v1\0";

#[derive(Debug, Clone)]
pub struct StartupKeys {
    pub local_key: [u8; AES256_KEY_BYTES],
}

pub async fn initialize() -> Result<StartupKeys> {
    let key_dir = Path::new(KEY_DIR);
    ensure_private_dir(key_dir).await?;

    let local_key_path = key_dir.join(LOCAL_KEY_FILE);
    let local_key = read_or_create_local_key(&local_key_path).await?;

    if !has_existing_pairing_keys(key_dir).await? {
        create_temp_pairing_key(key_dir, &local_key).await?;
    }

    Ok(StartupKeys { local_key })
}

async fn ensure_private_dir(path: &Path) -> Result {
    create_dir_all(path).await?;
    set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

async fn write_private_file(path: &Path, contents: &[u8]) -> Result {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(contents).await?;
    set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

async fn read_or_create_local_key(path: &Path) -> Result<[u8; AES256_KEY_BYTES]> {
    match read(path).await {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| Error::EncryptionError("local key must be 32 bytes")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; AES256_KEY_BYTES];
            OsRng.fill_bytes(&mut key);
            write_private_file(path, &key).await?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

async fn has_existing_pairing_keys(key_dir: &Path) -> Result<bool> {
    Ok(has_device_keys(key_dir).await? || has_temp_pairing_keys(key_dir).await?)
}

async fn has_device_keys(key_dir: &Path) -> Result<bool> {
    let android_dir = key_dir.join(DEVICE_KEYS_DIR).join("android");
    let mut entries = match read_dir(android_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            match metadata(entry.path().join(ENC_SECRET_KEY_FILE)).await {
                Ok(_) => return Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    Ok(false)
}

async fn has_temp_pairing_keys(key_dir: &Path) -> Result<bool> {
    match metadata(
        key_dir
            .join(TEMP_PAIRING_KEYS_DIR)
            .join(ENC_SECRET_KEY_FILE),
    )
    .await
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

async fn create_temp_pairing_key(key_dir: &Path, local_key: &[u8; AES256_KEY_BYTES]) -> Result {
    let temp_dir = key_dir.join(TEMP_PAIRING_KEYS_DIR);
    ensure_private_dir(&temp_dir).await?;

    let mut secret_key = [0u8; AES256_KEY_BYTES];
    OsRng.fill_bytes(&mut secret_key);

    let token = generate_pairing_token();
    let token_key = derive_token_key(&token)?;

    let locally_encrypted = encrypt_aes256_gcm(local_key, &secret_key)?;
    let token_encrypted = encrypt_aes256_gcm(&token_key, &locally_encrypted)?;

    write_private_file(&temp_dir.join(ENC_SECRET_KEY_FILE), &token_encrypted).await?;

    println!("Initial Alohomora pairing token: {token}");

    Ok(())
}

fn generate_pairing_token() -> String {
    let mut token_bytes = [0u8; AES256_KEY_BYTES];
    OsRng.fill_bytes(&mut token_bytes);
    format!("alohomora-{}", hex_encode(&token_bytes))
}

fn derive_token_key(token: &str) -> Result<[u8; AES256_KEY_BYTES]> {
    let hk = Hkdf::<Sha256>::new(None, token.as_bytes());
    let mut key = [0u8; AES256_KEY_BYTES];
    hk.expand(b"alohomora temp pairing token aes256 key", &mut key)
        .map_err(|_| Error::EncryptionError("failed to derive token key"))?;
    Ok(key)
}

fn encrypt_aes256_gcm(key: &[u8; AES256_KEY_BYTES], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::EncryptionError("invalid AES256 key length"))?;

    let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::EncryptionError("AES256-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(ENCRYPTED_BLOB_MAGIC.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(ENCRYPTED_BLOB_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn key_to_passphrase(key: &[u8; AES256_KEY_BYTES]) -> String {
    hex_encode(key)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
