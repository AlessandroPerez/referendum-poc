//! Typed HTTP client for the Registration Teller (RT) service (M4).

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::ristretto::RistrettoGroup;
use evoting::api::prelude::VotingCredentialBuilder;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Request body for `POST /sign`.
#[derive(Debug, Clone, Serialize)]
pub struct SignRequest {
    pub data: String,
    pub timestamp: i64,
}

/// Response from `POST /sign`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignResponse {
    pub entity_id: String,
    pub timestamp: i64,
    pub signature: String,
}

/// Response from `POST /decoy`.
#[derive(Debug, Clone, Deserialize)]
pub struct DecoyResponse {
    pub builder: VotingCredentialBuilder<RistrettoGroup>,
    pub pin: usize,
}

/// Response from `GET /status`.
#[derive(Debug, Clone, Deserialize)]
pub struct StatusResponse {
    pub entity_id: String,
    pub status: String,
}

/// Client for one RT server.
#[derive(Clone, Debug)]
pub struct RtClient {
    client: Client,
    base_url: Url,
    token: SecretString,
}

impl RtClient {
    /// Build a client for `base_url` with the service bearer token required by
    /// `POST /sign` and `POST /decoy`.
    pub fn new(client: Client, mut base_url: Url, token: SecretString) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self {
            client,
            base_url,
            token,
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.expose_secret())
    }

    /// `POST /sign` — ask the RT to sign a WBB data string.
    pub async fn sign(&self, data: &str, timestamp: i64) -> Result<SignResponse, RtError> {
        let url = self.base_url.join("sign")?;
        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth_header())
            .json(&SignRequest {
                data: data.to_string(),
                timestamp,
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(RtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(RtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(RtError::Json)
        } else {
            Err(RtError::Http(status, body))
        }
    }

    /// Convert a [`SignResponse`] into a [`crate::clients::wbb::SignedEntry`].
    pub fn to_signed_entry(
        data: &str,
        response: &SignResponse,
    ) -> Result<crate::clients::wbb::SignedEntry, RtError> {
        use ed25519_dalek::Signature;
        let signature = BASE64
            .decode(&response.signature)
            .map_err(RtError::Base64)?;
        let bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| RtError::InvalidSignature)?;
        let signature = Signature::from_bytes(&bytes);
        Ok(crate::clients::wbb::SignedEntry {
            data: data.as_bytes().to_vec(),
            timestamp: response.timestamp,
            entity_id: response.entity_id.clone(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// `POST /decoy` — request a decoy credential builder and ruse PIN.
    pub async fn decoy(&self) -> Result<DecoyResponse, RtError> {
        let url = self.base_url.join("decoy")?;
        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth_header())
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(RtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(RtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(RtError::Json)
        } else {
            Err(RtError::Http(status, body))
        }
    }

    /// `GET /status`.
    pub async fn status(&self) -> Result<StatusResponse, RtError> {
        let url = self.base_url.join("status")?;
        let response = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(RtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(RtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(RtError::Json)
        } else {
            Err(RtError::Http(status, body))
        }
    }
}

/// Errors from the RT client.
#[derive(Debug, thiserror::Error)]
pub enum RtError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid signature length")]
    InvalidSignature,
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
}
