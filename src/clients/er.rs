//! Typed HTTP client for the Electoral Roll (ER) service.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

use secrecy::{ExposeSecret, SecretString};

use crate::clients::dip::DipAssertion;
use crate::domain::{TokenValue, Vid};
use crate::protocol::acc::CredentialPackage;

/// Request body for `POST /login`.
#[derive(Debug, Clone, Serialize)]
pub struct LoginRequest {
    pub assertion: DipAssertion,
    pub signature: String,
}

/// Response from `POST /login`.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub vid: Vid,
    pub registration_token: TokenValue,
    pub credential_package: CredentialPackage,
}

/// Request body for `POST /devices`.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRegisterRequest {
    pub registration_token: TokenValue,
    pub pk_dv: String,
    pub at_pk: String,
}

/// Response from `POST /tokens/pin-request`.
#[derive(Debug, Clone, Deserialize)]
pub struct PinRequestTokensResponse {
    pub rid: String,
    pub rt_tokens: Vec<TokenValue>,
    pub ns_token: TokenValue,
}

/// Response from `POST /tokens/retrieval`.
#[derive(Debug, Clone, Deserialize)]
pub struct RetrievalTokensResponse {
    pub retrieval_tokens: Vec<TokenValue>,
}

/// Request body for `POST /tokens/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyTokenRequest {
    pub token: TokenValue,
    pub expected_type: Option<String>,
    pub consume: bool,
}

/// Response from `POST /tokens/verify`.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyTokenResponse {
    pub valid: bool,
    pub token_type: Option<String>,
    pub vid: Option<Vid>,
    pub rid: Option<String>,
}

/// Client for the ER service.
#[derive(Clone, Debug)]
pub struct ErClient {
    client: Client,
    base_url: Url,
}

impl ErClient {
    pub fn new(client: Client, mut base_url: Url) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self { client, base_url }
    }

    pub async fn login(
        &self,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<LoginResponse, ErError> {
        let url = self.base_url.join("login")?;
        let response = self
            .client
            .post(url)
            .json(&LoginRequest {
                assertion: assertion.clone(),
                signature: signature.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(ErError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(ErError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(ErError::Json)
        } else {
            Err(ErError::Http(status, body))
        }
    }

    pub async fn register_device(
        &self,
        registration_token: &TokenValue,
        pk_dv: &str,
        at_pk: &str,
    ) -> Result<(), ErError> {
        let url = self.base_url.join("devices")?;
        let response = self
            .client
            .post(url)
            .json(&DeviceRegisterRequest {
                registration_token: registration_token.clone(),
                pk_dv: pk_dv.to_string(),
                at_pk: at_pk.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(ErError::Network)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.map_err(ErError::Network)?;
            Err(ErError::Http(status, body))
        }
    }

    pub async fn pin_request_tokens(
        &self,
        registration_token: &TokenValue,
    ) -> Result<PinRequestTokensResponse, ErError> {
        let url = self.base_url.join("tokens/pin-request")?;
        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {registration_token}"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(ErError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(ErError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(ErError::Json)
        } else {
            Err(ErError::Http(status, body))
        }
    }

    pub async fn retrieval_tokens(
        &self,
        registration_token: &TokenValue,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<RetrievalTokensResponse, ErError> {
        let url = self.base_url.join("tokens/retrieval")?;
        #[derive(Serialize)]
        struct Req {
            assertion: DipAssertion,
            signature: String,
        }
        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {registration_token}"))
            .json(&Req {
                assertion: assertion.clone(),
                signature: signature.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(ErError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(ErError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(ErError::Json)
        } else {
            Err(ErError::Http(status, body))
        }
    }

    /// Verify a token with the ER; `expected_type` narrows the accepted token
    /// class and `consume` atomically marks a single-use token as spent.
    /// Requires the shared internal-API token (§6.1) — this is a
    /// service-to-service call, never made by voter clients.
    pub async fn verify_token(
        &self,
        token: &TokenValue,
        expected_type: Option<&str>,
        consume: bool,
        internal_token: &SecretString,
    ) -> Result<VerifyTokenResponse, ErError> {
        let url = self.base_url.join("tokens/verify")?;
        let response = self
            .client
            .post(url)
            .header(
                "Authorization",
                format!("Bearer {}", internal_token.expose_secret()),
            )
            .json(&VerifyTokenRequest {
                token: token.clone(),
                expected_type: expected_type.map(str::to_string),
                consume,
            })
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(ErError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(ErError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(ErError::Json)
        } else {
            Err(ErError::Http(status, body))
        }
    }
}

/// Errors from the ER client.
#[derive(Debug, thiserror::Error)]
pub enum ErError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
}
