use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{debug, info, warn};
use serde::Serialize;
use tokio::{
    sync::{oneshot, Mutex},
    time,
};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    dbus_server::SecretAccessor,
    error::{Error, Result},
    key_store::{self, SecureKey},
};

const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AuthGate {
    inner: Arc<AuthGateInner>,
}

impl fmt::Debug for AuthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthGate")
            .field("domain", &self.inner.domain)
            .field("external_port", &self.inner.external_port)
            .finish_non_exhaustive()
    }
}

struct AuthGateInner {
    local_key: SecureKey,
    domain: String,
    external_port: u16,
    pending: Mutex<HashMap<String, oneshot::Sender<SecureKey>>>,
}

#[derive(Debug, Serialize)]
struct AndroidAuthPayload {
    request_uuid: String,
    encrypted_blob: String,
    uid: String,
    username: String,
    pid: String,
    process_name: String,
    access_timestamp_ms: String,
    domain: String,
    port: String,
}

impl AuthGate {
    pub fn new(config: &AppConfig, local_key: SecureKey) -> Self {
        Self {
            inner: Arc::new(AuthGateInner {
                local_key,
                domain: config.domain.clone(),
                external_port: config.external_port,
                pending: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn local_key(&self) -> &SecureKey {
        &self.inner.local_key
    }

    pub async fn request_secret_key(
        &self,
        accessor: Option<&SecretAccessor<'_>>,
    ) -> Result<SecureKey> {
        let devices = key_store::list_android_device_auth_blobs().await?;
        if devices.is_empty() {
            warn!("Secret access requested but no Android devices are registered");
            return Err(Error::PermissionDenied);
        }

        let request_uuid = Uuid::new_v4().to_string();
        let (sender, receiver) = oneshot::channel();

        {
            let mut pending = self.inner.pending.lock().await;
            pending.insert(request_uuid.clone(), sender);
        }

        for device in devices {
            // Decrypt the device registration to retrieve the FCM token
            let registration = match key_store::read_android_device_registration(&device.device_uuid, &self.inner.local_key).await {
                Ok(reg) => reg,
                Err(err) => {
                    warn!("Failed to read registration for device {}: {}", device.device_uuid, err);
                    continue;
                }
            };

            let fcm_token = match registration["fcm"]["token"].as_str() {
                Some(t) => t.to_string(),
                None => {
                    warn!("FCM token not found in registration for device {}", device.device_uuid);
                    continue;
                }
            };

            let encrypted_blob = device
                .encrypted_secret_key
                .unlock_slice(|encrypted| BASE64.encode(encrypted));
            let payload = AndroidAuthPayload {
                request_uuid: request_uuid.clone(),
                encrypted_blob,
                uid: accessor.map(|a| a.uid).unwrap_or_default().to_string(),
                username: optional_string(accessor.and_then(|a| a.username.as_ref())),
                pid: accessor.map(|a| a.pid).unwrap_or_default().to_string(),
                process_name: optional_string(accessor.and_then(|a| a.process_name.as_ref())),
                access_timestamp_ms: accessor
                    .map(|a| a.timestamp)
                    .unwrap_or_default()
                    .to_string(),
                domain: self.inner.domain.clone(),
                port: self.inner.external_port.to_string(),
            };

            let request_body = serde_json::json!({
                "token": fcm_token,
                "request_uuid": payload.request_uuid,
                "encrypted_blob": payload.encrypted_blob,
                "uid": payload.uid,
                "username": payload.username,
                "pid": payload.pid,
                "process_name": payload.process_name,
                "access_timestamp_ms": payload.access_timestamp_ms,
                "domain": payload.domain,
                "port": payload.port,
            });

            let client = reqwest::Client::new();
            let url = std::env::var("ALOHOMORA_NOTIFICATION_URL")
                .unwrap_or_else(|_| "https://alohomora.app/send-notification".to_string());

            info!("Sending push notification to web service for device: {}", device.device_uuid);
            match client.post(&url).json(&request_body).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!("Successfully sent notification request to web service for device {}", device.device_uuid);
                    } else {
                        warn!("Web service returned error status when sending notification to device {}: {}", device.device_uuid, resp.status());
                        if let Ok(text) = resp.text().await {
                            warn!("Response body: {}", text);
                        }
                    }
                }
                Err(err) => {
                    warn!("Failed to send notification request to web service for device {}: {}", device.device_uuid, err);
                }
            }
        }

        match time::timeout(AUTHORIZATION_TIMEOUT, receiver).await {
            Ok(Ok(secret_key)) => {
                debug!("Authentication gate opened for request {request_uuid}");
                Ok(secret_key)
            }
            Ok(Err(_)) => {
                self.inner.pending.lock().await.remove(&request_uuid);
                Err(Error::PermissionDenied)
            }
            Err(_) => {
                self.inner.pending.lock().await.remove(&request_uuid);
                warn!("Authentication request {request_uuid} timed out");
                Err(Error::PermissionDenied)
            }
        }
    }

    pub async fn complete_authentication(
        &self,
        request_uuid: &str,
        decrypted_blob_b64: &str,
    ) -> Result {
        let locally_encrypted = BASE64
            .decode(decrypted_blob_b64)
            .map_err(|_| Error::InvalidRequest("decrypted_blob_b64 is not valid base64".into()))?;
        let secret_key = key_store::decrypt_aes256_gcm(&self.inner.local_key, &locally_encrypted)?;
        let secret_key = SecureKey::try_from(secret_key)
            .map_err(|_| Error::EncryptionError("decrypted secret key must be 32 bytes"))?;

        let sender = self
            .inner
            .pending
            .lock()
            .await
            .remove(request_uuid)
            .ok_or_else(|| Error::InvalidRequest("no pending authentication request".into()))?;

        sender
            .send(secret_key)
            .map_err(|_| Error::InvalidRequest("authentication request is no longer active".into()))
    }
}

fn optional_string(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}
