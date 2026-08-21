//! Typed HTTP client for the Digital Identity Provider (DIP) service.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

/// Request body for `POST /authenticate`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticateRequest {
    pub fiscal_id: String,
}

/// DIP assertion about a voter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DipAssertion {
    pub fiscal_id: String,
    pub name: String,
    pub assurance: String,
}

/// Response from `POST /authenticate`.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateResponse {
    pub assertion: DipAssertion,
    pub signature: String,
    pub verifying_key: String,
}

/// Client for the DIP service.
#[derive(Clone, Debug)]
pub struct DipClient {
    client: Client,
    base_url: Url,
}

impl DipClient {
    pub fn new(client: Client, mut base_url: Url) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self { client, base_url }
    }

    /// `POST /authenticate` — obtain a signed DIP assertion.
    pub async fn authenticate(&self, fiscal_id: &str) -> Result<AuthenticateResponse, DipError> {
        let url = self.base_url.join("authenticate")?;
        let response = self
            .client
            .post(url)
            .json(&AuthenticateRequest {
                fiscal_id: fiscal_id.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(DipError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(DipError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(DipError::Json)
        } else {
            Err(DipError::Http(status, body))
        }
    }
}

/// Errors from the DIP client.
#[derive(Debug, thiserror::Error)]
pub enum DipError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
}
