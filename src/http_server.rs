use std::net::{Ipv4Addr, SocketAddr};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{debug, error, info};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, sha2::Sha256, Oaep, RsaPublicKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    config::AppConfig,
    error::{Error, Result},
    key_store::{self, SecureBlob, SecureKey},
};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeychainInfo {
    pub domain: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyParameters {
    pub digest: String,
    pub mgf: String,
    pub mgf_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub format: String,
    pub value_b64: String,
    pub parameters: PublicKeyParameters,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FcmInfo {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub os: String,
    pub sdk_int: u32,
    pub release: String,
    pub manufacturer: String,
    pub model: String,
    pub product: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub schema_version: u32,
    pub device_uuid: String,
    pub keychain: KeychainInfo,
    #[serde(default)]
    pub initialisation_token: Option<String>,
    pub public_key: PublicKeyInfo,
    pub fcm: FcmInfo,
    pub app: AppInfo,
    pub device: DeviceInfo,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticateRequest {
    pub schema_version: u32,
    pub request_uuid: String,
    pub device_uuid: String,
    pub keychain: KeychainInfo,
    pub decrypted_blob_b64: String,
    pub app: AppInfo,
    pub approved_at_ms: i64,
}

#[derive(Clone)]
struct ApiState {
    local_key: SecureKey,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidRequest(message) => Self::bad_request(message),
            err => Self::internal(err.to_string()),
        }
    }
}

pub async fn spawn(config: AppConfig, local_key: SecureKey) -> Result<JoinHandle<()>> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.internal_port));
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Alohomora HTTP server listening on {} for {}:{}",
        addr, config.domain, config.external_port
    );

    let app = Router::new()
        .route("/register", post(register))
        .route("/authenticate", post(authenticate))
        .with_state(ApiState { local_key });

    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            error!("Alohomora HTTP server failed: {err}");
        }
    }))
}

async fn register(
    State(state): State<ApiState>,
    Json(request): Json<RegisterRequest>,
) -> std::result::Result<StatusCode, ApiError> {
    debug!(
        "Received registration request for {}:{} from {} {}",
        request.keychain.domain,
        request.keychain.port,
        request.device.manufacturer,
        request.device.model
    );

    if request.device.os != "Android" {
        return Err(ApiError::bad_request(
            "only Android registrations are supported",
        ));
    }

    let initialisation_token = request
        .initialisation_token
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("initialisation_token is required"))?;

    validate_public_key_info(&request.public_key)?;

    let secret_key =
        key_store::read_temp_secret_key(initialisation_token, &state.local_key).await?;
    let locally_encrypted_secret_key = secret_key
        .unlock(|secret_key| key_store::encrypt_aes256_gcm(&state.local_key, secret_key))?;
    let encrypted_secret_key = locally_encrypted_secret_key.unlock_slice(|encrypted| {
        encrypt_with_registration_public_key(&request.public_key, encrypted)
    })?;

    let registration_json = serde_json::to_vec(&request)
        .map_err(|err| ApiError::internal(format!("failed to serialize registration: {err}")))?;
    let encrypted_registration =
        key_store::encrypt_aes256_gcm(&state.local_key, &registration_json)?;

    key_store::store_android_device_registration(
        &request.device_uuid,
        &encrypted_registration,
        &encrypted_secret_key,
    )
    .await?;

    info!(
        "Registered Android device {} at device-keys/android/{}",
        request.device.model, request.device_uuid
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate(Json(request): Json<AuthenticateRequest>) -> StatusCode {
    debug!(
        "Received authentication approval for request {} from {}",
        request.request_uuid, request.app.package_name
    );
    StatusCode::NO_CONTENT
}

fn validate_public_key_info(public_key: &PublicKeyInfo) -> std::result::Result<(), ApiError> {
    if public_key.algorithm != "RSA-OAEP-256" {
        return Err(ApiError::bad_request(
            "public_key.algorithm must be RSA-OAEP-256",
        ));
    }
    if public_key.format != "X.509 SubjectPublicKeyInfo" {
        return Err(ApiError::bad_request(
            "public_key.format must be X.509 SubjectPublicKeyInfo",
        ));
    }
    if public_key.parameters.digest != "SHA-256"
        || public_key.parameters.mgf != "MGF1"
        || public_key.parameters.mgf_digest != "SHA-256"
    {
        return Err(ApiError::bad_request(
            "public_key.parameters must specify SHA-256/MGF1/SHA-256",
        ));
    }
    Ok(())
}

fn encrypt_with_registration_public_key(
    public_key: &PublicKeyInfo,
    plaintext: &[u8],
) -> std::result::Result<SecureBlob, ApiError> {
    let public_key_der = BASE64
        .decode(&public_key.value_b64)
        .map_err(|_| ApiError::bad_request("public_key.value_b64 is not valid base64"))?;
    let public_key = RsaPublicKey::from_public_key_der(&public_key_der)
        .map_err(|_| ApiError::bad_request("public_key.value_b64 is not a valid SPKI RSA key"))?;

    public_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), plaintext)
        .map_err(|err| ApiError::bad_request(format!("RSA-OAEP-256 encryption failed: {err}")))
        .and_then(|encrypted| key_store::secure_blob_from_vec(encrypted).map_err(ApiError::from))
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::{AuthenticateRequest, RegisterRequest};

    #[test]
    fn register_request_has_json_schema() {
        let schema = schema_for!(RegisterRequest);
        assert_eq!(
            schema.schema.metadata.unwrap().title.unwrap(),
            "RegisterRequest"
        );
    }

    #[test]
    fn authenticate_request_has_json_schema() {
        let schema = schema_for!(AuthenticateRequest);
        assert_eq!(
            schema.schema.metadata.unwrap().title.unwrap(),
            "AuthenticateRequest"
        );
    }

    #[test]
    fn register_request_parses_expected_payload() {
        let payload = r#"{
            "schema_version": 1,
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443
            },
            "initialisation_token": "optional-token",
            "public_key": {
              "algorithm": "RSA-OAEP-256",
              "format": "X.509 SubjectPublicKeyInfo",
              "value_b64": "base64-public-key",
              "parameters": {
                "digest": "SHA-256",
                "mgf": "MGF1",
                "mgf_digest": "SHA-256"
              }
            },
            "fcm": {
              "token": "firebase-registration-token"
            },
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "device": {
              "os": "Android",
              "sdk_int": 36,
              "release": "16",
              "manufacturer": "Google",
              "model": "Pixel",
              "product": "pixel"
            },
            "registered_at_ms": 1760000000000
        }"#;

        let request: RegisterRequest = serde_json::from_str(payload).unwrap();
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.device_uuid, "f2018f87-e926-42a1-8b48-9ad4b7fd7cde");
        assert_eq!(
            request.initialisation_token.as_deref(),
            Some("optional-token")
        );
        assert_eq!(request.public_key.parameters.mgf_digest, "SHA-256");
    }

    #[test]
    fn authenticate_request_parses_expected_payload() {
        let payload = r#"{
            "schema_version": 1,
            "request_uuid": "6fbbce84-5aef-43c3-8cc7-469cbfd83109",
            "device_uuid": "f2018f87-e926-42a1-8b48-9ad4b7fd7cde",
            "keychain": {
              "domain": "example.com",
              "port": 443
            },
            "decrypted_blob_b64": "base64-decrypted-blob",
            "app": {
              "package_name": "com.alohomora.app",
              "version_name": "0.1.0",
              "version_code": 1
            },
            "approved_at_ms": 1760000000123
        }"#;

        let request: AuthenticateRequest = serde_json::from_str(payload).unwrap();
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.request_uuid, "6fbbce84-5aef-43c3-8cc7-469cbfd83109");
        assert_eq!(request.device_uuid, "f2018f87-e926-42a1-8b48-9ad4b7fd7cde");
        assert_eq!(request.decrypted_blob_b64, "base64-decrypted-blob");
    }
}
