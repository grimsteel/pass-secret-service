use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use cuid2::CuidConstructor;
use hkdf::Hkdf;
use qrcode::{render::unicode, QrCode};
use rand::{rngs::OsRng, RngCore};
use secure_types::{SecureArray, SecureBytes, SecureString};
use sha2::Sha256;
use tokio::{
    fs::{
        create_dir_all, metadata, read, read_dir, set_permissions, OpenOptions as TokioOpenOptions,
    },
    io::{self, AsyncWriteExt},
};

use crate::{
    config::AppConfig,
    error::{Error, Result},
};

const KEY_DIR: &str = "/var/lib/alohomora-service";
const LOCAL_KEY_FILE: &str = "local_key.bin";
const DEVICE_KEYS_DIR: &str = "device-keys";
const ANDROID_DEVICE_KEYS_DIR: &str = "android";
const TEMP_PAIRING_KEYS_DIR: &str = "temp-pairing-keys";
const ENC_SECRET_KEY_FILE: &str = "enc_secret_key.bin";
const ENC_DEVICE_REGISTRATION_FILE: &str = "enc_device_registration.json";
pub const AES256_KEY_BYTES: usize = 32;
const AES_GCM_NONCE_BYTES: usize = 12;
const ENCRYPTED_BLOB_MAGIC: &[u8] = b"alohomora-aes256-gcm-v1\0";
const PAIRING_TOKEN_PREFIX: &str = "alohomora";
const PAIRING_TOKEN_ID_LEN: u16 = 10;
pub type SecureKey = SecureArray<u8, AES256_KEY_BYTES>;
pub type SecureBlob = SecureBytes;

#[derive(Clone)]
pub struct StartupKeys {
    pub local_key: SecureKey,
}

pub async fn initialize(config: &AppConfig) -> Result<StartupKeys> {
    let key_dir = Path::new(KEY_DIR);
    ensure_private_dir(key_dir).await?;

    let local_key_path = key_dir.join(LOCAL_KEY_FILE);
    let local_key = read_or_create_local_key(&local_key_path).await?;

    if !has_existing_pairing_keys(key_dir).await? {
        create_temp_pairing_key(key_dir, &local_key, config).await?;
    }

    Ok(StartupKeys { local_key })
}

async fn ensure_private_dir(path: &Path) -> Result {
    create_dir_all(path).await?;
    set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

async fn write_private_file(path: &Path, contents: &[u8]) -> Result {
    let mut file = TokioOpenOptions::new()
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

fn write_private_secure_file(path: &Path, contents: &SecureBlob) -> Result {
    contents.unlock_slice(|contents| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })
}

async fn read_or_create_local_key(path: &Path) -> Result<SecureKey> {
    match read(path).await {
        Ok(bytes) => secure_key_from_vec(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; AES256_KEY_BYTES];
            OsRng.fill_bytes(&mut key);
            write_private_file(path, &key).await?;
            secure_key_from_array(key)
        }
        Err(e) => Err(e.into()),
    }
}

async fn has_existing_pairing_keys(key_dir: &Path) -> Result<bool> {
    Ok(has_device_keys(key_dir).await? || has_temp_pairing_keys(key_dir).await?)
}

async fn has_device_keys(key_dir: &Path) -> Result<bool> {
    let android_dir = key_dir.join(DEVICE_KEYS_DIR).join(ANDROID_DEVICE_KEYS_DIR);
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
    let temp_dir = key_dir.join(TEMP_PAIRING_KEYS_DIR);
    let mut entries = match read_dir(temp_dir).await {
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

async fn create_temp_pairing_key(
    key_dir: &Path,
    local_key: &SecureKey,
    config: &AppConfig,
) -> Result {
    let pairing_token = generate_pairing_token();
    let temp_dir = temp_pairing_key_dir(key_dir, &pairing_token.id);
    ensure_private_dir(&temp_dir).await?;

    let mut secret_key = [0u8; AES256_KEY_BYTES];
    OsRng.fill_bytes(&mut secret_key);
    let secret_key = secure_key_from_array(secret_key)?;

    let token_key = derive_token_key(&pairing_token.value)?;

    let locally_encrypted =
        secret_key.unlock(|secret_key| encrypt_aes256_gcm(local_key, secret_key))?;
    let token_encrypted =
        locally_encrypted.unlock_slice(|encrypted| encrypt_aes256_gcm(&token_key, encrypted))?;

    write_private_secure_file(&temp_dir.join(ENC_SECRET_KEY_FILE), &token_encrypted)?;

    println!("Initial Alohomora pairing token: {}", pairing_token.value);
    print_setup_qr_code(&pairing_token.value, config)?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingToken {
    pub id: String,
    pub value: String,
}

fn generate_pairing_token() -> PairingToken {
    let id = CuidConstructor::new()
        .with_length(PAIRING_TOKEN_ID_LEN)
        .create_id();
    let mut token_bytes = [0u8; AES256_KEY_BYTES];
    OsRng.fill_bytes(&mut token_bytes);
    let encoded_token = bs58::encode(token_bytes).into_string();
    let value = format!("{PAIRING_TOKEN_PREFIX}-{id}-{encoded_token}");
    PairingToken { id, value }
}

pub fn parse_pairing_token(token: &str) -> Result<PairingToken> {
    let mut parts = token.splitn(3, '-');
    let prefix = parts.next();
    let id = parts.next();
    let encoded_token = parts.next();

    let (Some(PAIRING_TOKEN_PREFIX), Some(id), Some(encoded_token)) = (prefix, id, encoded_token)
    else {
        return Err(Error::InvalidRequest("invalid pairing token format".into()));
    };

    if id.len() != PAIRING_TOKEN_ID_LEN as usize || !cuid2::is_cuid2(id) {
        return Err(Error::InvalidRequest("invalid pairing token id".into()));
    }

    let token_bytes = bs58::decode(encoded_token)
        .into_vec()
        .map_err(|_| Error::InvalidRequest("invalid pairing token encoding".into()))?;
    if token_bytes.len() != AES256_KEY_BYTES {
        return Err(Error::InvalidRequest(
            "invalid pairing token entropy length".into(),
        ));
    }

    Ok(PairingToken {
        id: id.to_owned(),
        value: token.to_owned(),
    })
}

fn print_setup_qr_code(token: &str, config: &AppConfig) -> Result {
    let setup_url = format!(
        "https://alohomora.app/register?d={}&p={}&t={token}",
        config.domain, config.external_port
    );
    let qr_code =
        QrCode::new(setup_url.as_bytes()).map_err(|_| Error::EncryptionError("invalid QR data"))?;
    let qr = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();

    println!("Initial Alohomora setup URL: {setup_url}");
    println!("{qr}");

    Ok(())
}

fn derive_token_key(token: &str) -> Result<SecureKey> {
    let hk = Hkdf::<Sha256>::new(None, token.as_bytes());
    let mut key = [0u8; AES256_KEY_BYTES];
    hk.expand(b"alohomora temp pairing token aes256 key", &mut key)
        .map_err(|_| Error::EncryptionError("failed to derive token key"))?;
    secure_key_from_array(key)
}

pub fn encrypt_aes256_gcm(key: &SecureKey, plaintext: &[u8]) -> Result<SecureBlob> {
    key.unlock(|key| {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::EncryptionError("invalid AES256 key length"))?;

        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionError("AES256-GCM encryption failed"))?;

        let mut out =
            Vec::with_capacity(ENCRYPTED_BLOB_MAGIC.len() + nonce.len() + ciphertext.len());
        out.extend_from_slice(ENCRYPTED_BLOB_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        secure_blob_from_vec(out)
    })
}

pub fn decrypt_aes256_gcm(key: &SecureKey, encrypted: &[u8]) -> Result<SecureBlob> {
    if !encrypted.starts_with(ENCRYPTED_BLOB_MAGIC) {
        return Err(Error::EncryptionError("unknown encrypted blob format"));
    }

    let encrypted = &encrypted[ENCRYPTED_BLOB_MAGIC.len()..];
    if encrypted.len() < AES_GCM_NONCE_BYTES {
        return Err(Error::EncryptionError("encrypted blob missing nonce"));
    }

    let (nonce, ciphertext) = encrypted.split_at(AES_GCM_NONCE_BYTES);
    key.unlock(|key| {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::EncryptionError("invalid AES256 key length"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| Error::EncryptionError("AES256-GCM decryption failed"))?;
        secure_blob_from_vec(plaintext)
    })
}

pub async fn read_temp_secret_key(token: &str, local_key: &SecureKey) -> Result<SecureKey> {
    let pairing_token = parse_pairing_token(token)?;
    let token_key = derive_token_key(&pairing_token.value)?;
    let encrypted = secure_blob_from_vec(
        read(temp_pairing_key_dir(Path::new(KEY_DIR), &pairing_token.id).join(ENC_SECRET_KEY_FILE))
            .await?,
    )?;
    let locally_encrypted =
        encrypted.unlock_slice(|encrypted| decrypt_aes256_gcm(&token_key, encrypted))?;
    let secret_key = locally_encrypted
        .unlock_slice(|locally_encrypted| decrypt_aes256_gcm(local_key, locally_encrypted))?;

    SecureKey::try_from(secret_key).map_err(secure_memory_error)
}

pub async fn store_android_device_registration(
    device_uuid: &str,
    encrypted_registration_json: &SecureBlob,
    encrypted_secret_key: &SecureBlob,
) -> Result {
    let device_dir = Path::new(KEY_DIR)
        .join(DEVICE_KEYS_DIR)
        .join(ANDROID_DEVICE_KEYS_DIR)
        .join(device_uuid);
    ensure_private_dir(&device_dir).await?;
    write_private_secure_file(
        &device_dir.join(ENC_DEVICE_REGISTRATION_FILE),
        encrypted_registration_json,
    )?;
    write_private_secure_file(&device_dir.join(ENC_SECRET_KEY_FILE), encrypted_secret_key)?;
    Ok(())
}

fn temp_pairing_key_dir(key_dir: &Path, token_id: &str) -> PathBuf {
    key_dir.join(TEMP_PAIRING_KEYS_DIR).join(token_id)
}

pub fn key_to_passphrase(key: &SecureKey) -> SecureString {
    key.unlock(|key| SecureString::from(hex_encode(key)))
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

fn secure_key_from_array(key: [u8; AES256_KEY_BYTES]) -> Result<SecureKey> {
    let mut key = key;
    SecureKey::from_slice_mut(&mut key).map_err(secure_memory_error)
}

fn secure_key_from_vec(bytes: Vec<u8>) -> Result<SecureKey> {
    let key: [u8; AES256_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| Error::EncryptionError("local key must be 32 bytes"))?;
    secure_key_from_array(key)
}

pub fn secure_blob_from_vec(bytes: Vec<u8>) -> Result<SecureBlob> {
    SecureBlob::from_vec(bytes).map_err(secure_memory_error)
}

fn secure_memory_error(_: secure_types::Error) -> Error {
    Error::EncryptionError("secure memory operation failed")
}

#[cfg(test)]
mod tests {
    use super::{generate_pairing_token, parse_pairing_token, PAIRING_TOKEN_PREFIX};

    #[test]
    fn pairing_token_contains_cuid_and_base58_entropy() {
        let token = generate_pairing_token();
        let parsed = parse_pairing_token(&token.value).unwrap();

        assert_eq!(parsed.id, token.id);
        assert_eq!(parsed.value, token.value);
        assert!(token
            .value
            .starts_with(&format!("{PAIRING_TOKEN_PREFIX}-{}-", token.id)));
    }

    #[test]
    fn pairing_token_rejects_bad_format() {
        assert!(parse_pairing_token("alohomora-not-valid").is_err());
    }
}
