//! Typed HTTP client for the Electoral Roll (ER) service.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

use secrecy::{ExposeSecret, SecretString};

use crate::clients::dip::DipAssertion;
use crate::domain::{CommB, TokenValue, Vid};
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
    pub state_blob: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm_b: Option<CommB>,
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
        state_blob: Option<String>,
    ) -> Result<(), ErError> {
        let url = self.base_url.join("devices")?;
        let response = self
            .client
            .post(url)
            .json(&DeviceRegisterRequest {
                registration_token: registration_token.clone(),
                pk_dv: pk_dv.to_string(),
                at_pk: at_pk.to_string(),
                state_blob,
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
                comm_b: None,
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

    /// `POST /devices/blob` — refresh the encrypted recovery blob (V8).
    pub async fn upload_device_blob(
        &self,
        registration_token: &TokenValue,
        state_blob: &str,
    ) -> Result<(), ErError> {
        #[derive(Serialize)]
        struct Req {
            registration_token: TokenValue,
            state_blob: String,
        }
        let url = self.base_url.join("devices/blob")?;
        let response = self
            .client
            .post(url)
            .json(&Req {
                registration_token: registration_token.clone(),
                state_blob: state_blob.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(ErError::Network)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.map_err(ErError::Network)?;
            Err(ErError::Http(status, body))
        }
    }

    /// `POST /devices/recover` — fetch the encrypted recovery blob (V8).
    pub async fn recover_device(
        &self,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<DeviceRecoverResponse, ErError> {
        #[derive(Serialize)]
        struct Req {
            assertion: DipAssertion,
            signature: String,
        }
        let url = self.base_url.join("devices/recover")?;
        let response = self
            .client
            .post(url)
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

    /// `POST /revocations` — revoke the caller's credential, re-issue a
    /// spare vid (V9, §3.7.5).
    pub async fn revoke(
        &self,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<RevocationResponse, ErError> {
        #[derive(Serialize)]
        struct Req {
            assertion: DipAssertion,
            signature: String,
        }
        let url = self.base_url.join("revocations")?;
        let response = self
            .client
            .post(url)
            .json(&Req {
                assertion: assertion.clone(),
                signature: signature.to_string(),
            })
            .timeout(Duration::from_secs(20))
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

    /// `GET /voters/eligible` — the current eligible vid list (A7).
    pub async fn eligible(&self) -> Result<EligibleResponse, ErError> {
        let url = self.base_url.join("voters/eligible")?;
        let response = self
            .client
            .get(url)
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

    /// `POST /admin/eligible-vids` — publish the eligible vid list to the
    /// WBB at tally start (M8, A7).  Requires the ER admin token.
    pub async fn publish_eligible_vids(
        &self,
        admin_token: &SecretString,
    ) -> Result<EligibleResponse, ErError> {
        let url = self.base_url.join("admin/eligible-vids")?;
        let response = self
            .client
            .post(url)
            .header(
                "Authorization",
                format!("Bearer {}", admin_token.expose_secret()),
            )
            .timeout(Duration::from_secs(15))
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

    /// `POST /tokens/casting` — request anonymous casting tokens for `comm_b`
    /// (§5.3.1.6). `signature` is the base64 EdDSA signature over the commB
    /// bytes made with the voter's app key.
    pub async fn casting_tokens(
        &self,
        registration_token: &TokenValue,
        comm_b: &CommB,
        signature: &str,
    ) -> Result<CastingTokensResponse, ErError> {
        let url = self.base_url.join("tokens/casting")?;
        #[derive(Serialize)]
        struct Req {
            comm_b: CommB,
            signature: String,
        }
        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {registration_token}"))
            .json(&Req {
                comm_b: *comm_b,
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

    /// Like [`ErClient::verify_token`] but also presents the observed `comm_b`
    /// so the ER can check the casting-token binding (§5.3.1.6).
    pub async fn verify_token_with_comm_b(
        &self,
        token: &TokenValue,
        expected_type: Option<&str>,
        consume: bool,
        comm_b: &CommB,
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
                comm_b: Some(*comm_b),
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

/// Response from `POST /devices/recover`.
#[derive(Clone, Deserialize)]
pub struct DeviceRecoverResponse {
    pub vid: Vid,
    pub state_blob: String,
}

impl std::fmt::Debug for DeviceRecoverResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRecoverResponse")
            .field("vid", &self.vid)
            .field("state_blob", &"<opaque>")
            .finish()
    }
}

/// Response from `POST /revocations`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevocationResponse {
    pub vid: Vid,
    pub registration_token: TokenValue,
    pub credential_package: crate::protocol::acc::CredentialPackage,
}

/// Response from `GET /voters/eligible`.
#[derive(Debug, Clone, Deserialize)]
pub struct EligibleResponse {
    pub vids: Vec<Vid>,
}

/// Response from `POST /tokens/casting`.
#[derive(Debug, Clone, Deserialize)]
pub struct CastingTokensResponse {
    pub casting_tokens: Vec<TokenValue>,
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
