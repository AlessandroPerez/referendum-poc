//! Typed HTTP client for the Registration Teller (RT) service.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::{GroupPoint, GroupScalar};
use dlog_group::ristretto::RistrettoGroup;
use evoting::api::prelude::{ThresholdDvRound1Broadcast, VotingCredentialBuilder};
use evoting::api::server::rt::AccShareBroadcast;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::domain::TokenValue;

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

    /// `POST /sign` - ask the RT to sign a WBB data string.
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

    /// `POST /decoy` - request a decoy credential builder and ruse PIN.
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

    /// `POST /credentials/request` - record a PIN request for `rid`, authorized
    /// by an ER-issued single-use PIN-request token (Sec. 5.3.1.3).
    /// Returns the sampled tau delay in logical-clock ticks.
    pub async fn credentials_request(&self, token: &TokenValue, rid: &str) -> Result<u64, RtError> {
        let url = self.base_url.join("credentials/request")?;
        #[derive(Serialize)]
        struct Req {
            token: TokenValue,
            rid: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            tau_ticks: u64,
        }
        let response = self
            .client
            .post(url)
            .json(&Req {
                token: token.clone(),
                rid: rid.to_string(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(RtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(RtError::Network)?;
        if status.is_success() {
            let resp: Resp = serde_json::from_str(&body).map_err(RtError::Json)?;
            Ok(resp.tau_ticks)
        } else {
            Err(RtError::Http(status, body))
        }
    }

    /// `POST /credentials/deliver` - retrieve this RT's `AccShareBroadcast`.
    pub async fn credentials_deliver(
        &self,
        token: &TokenValue,
    ) -> Result<AccShareBroadcast<RistrettoGroup>, RtError> {
        let url = self.base_url.join("credentials/deliver")?;
        #[derive(Serialize)]
        struct Req {
            token: TokenValue,
        }
        let response = self
            .client
            .post(url)
            .json(&Req {
                token: token.clone(),
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

    /// `POST /dvnizkp/round1` - start the DVNIZKP protocol.
    pub async fn dvnizkp_round1(
        &self,
        token: &TokenValue,
        a: &<RistrettoGroup as GroupPoint>::Point,
    ) -> Result<ThresholdDvRound1Broadcast<RistrettoGroup>, RtError> {
        let url = self.base_url.join("dvnizkp/round1")?;
        #[derive(Serialize)]
        struct Req {
            token: TokenValue,
            #[serde(with = "dlog_group::serde::PointHelper::<RistrettoGroup>")]
            a: <RistrettoGroup as GroupPoint>::Point,
        }
        let response = self
            .client
            .post(url)
            .json(&Req {
                token: token.clone(),
                a: *a,
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

    /// `POST /dvnizkp/round2` - obtain the round-2 scalar share.
    pub async fn dvnizkp_round2(
        &self,
        token: &TokenValue,
        c1: &<RistrettoGroup as GroupScalar>::Scalar,
        all_ids: &[usize],
    ) -> Result<<RistrettoGroup as GroupScalar>::Scalar, RtError> {
        let url = self.base_url.join("dvnizkp/round2")?;
        #[derive(Serialize)]
        struct Req {
            token: TokenValue,
            #[serde(with = "dlog_group::serde::ScalarHelper::<RistrettoGroup>")]
            c1: <RistrettoGroup as GroupScalar>::Scalar,
            all_ids: Vec<usize>,
        }
        let response = self
            .client
            .post(url)
            .json(&Req {
                token: token.clone(),
                c1: *c1,
                all_ids: all_ids.to_vec(),
            })
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(RtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(RtError::Network)?;
        if status.is_success() {
            #[derive(Deserialize)]
            struct Resp {
                #[serde(with = "dlog_group::serde::ScalarHelper::<RistrettoGroup>")]
                z1: <RistrettoGroup as GroupScalar>::Scalar,
            }
            let resp: Resp = serde_json::from_str(&body).map_err(RtError::Json)?;
            Ok(resp.z1)
        } else {
            Err(RtError::Http(status, body))
        }
    }

    /// `POST /controls/round1` - open a credential-control session over the
    /// shuffled votes (Sec. 3.9 steps 14-19).
    pub async fn controls_round1(
        &self,
        votes: &[evoting::api::prelude::Vote<RistrettoGroup>],
    ) -> Result<evoting::api::prelude::PartialControlBroadcast<RistrettoGroup>, RtError> {
        let url = self.base_url.join("controls/round1")?;
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Req<'a> {
            votes: &'a [evoting::api::prelude::Vote<RistrettoGroup>],
        }
        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth_header())
            .json(&Req { votes })
            .timeout(Duration::from_secs(30))
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

    /// `POST /controls/round2` - obtain this RT's control response; consumes
    /// the session.
    pub async fn controls_round2(
        &self,
        all_round1: &[evoting::api::prelude::PartialControlBroadcast<RistrettoGroup>],
        all_ids: &[usize],
    ) -> Result<evoting::api::prelude::PartialControlResponse<RistrettoGroup>, RtError> {
        let url = self.base_url.join("controls/round2")?;
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Req<'a> {
            all_round1: &'a [evoting::api::prelude::PartialControlBroadcast<RistrettoGroup>],
            all_ids: &'a [usize],
        }
        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth_header())
            .json(&Req {
                all_round1,
                all_ids,
            })
            .timeout(Duration::from_secs(30))
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
