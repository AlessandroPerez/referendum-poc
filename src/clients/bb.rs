//! Typed HTTP client for the Ballot Box (BB) service.

use std::time::Duration;

use dlog_group::ristretto::RistrettoGroup;
use evoting::api::client::Ballot;
use evoting::api::prelude::{DiscloseCAI, Receipt};
use evoting::api::server::bb::BallotRecord;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::domain::{BallotDigest, TokenValue};

type G = RistrettoGroup;

/// Response from `POST /ballots`.
#[derive(Debug, Clone, Deserialize)]
pub struct CastResponse {
    pub digest: BallotDigest,
    pub receipt: Receipt,
    pub emoji: Vec<String>,
}

/// Response from `POST /cai`.
#[derive(Debug, Clone, Deserialize)]
pub struct CaiResponse {
    pub digest: BallotDigest,
    pub confirmed_at_ms: u64,
    /// The values the ballot box opened and published.
    pub opened: evoting::api::prelude::OpenedCai,
}

/// Response from `GET /receipts/{digest}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiptResponse {
    pub digest: BallotDigest,
    pub receipt: Receipt,
    pub emoji: Vec<String>,
    pub cai_confirmed: bool,
}

/// Client for one BB server.
#[derive(Clone, Debug)]
pub struct BbClient {
    client: Client,
    base_url: Url,
}

impl BbClient {
    pub fn new(client: Client, mut base_url: Url) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self { client, base_url }
    }

    /// `POST /ballots` - cast a ballot with a CAT casting token (Sec. 3.8.4).
    pub async fn cast(
        &self,
        ballot: &Ballot<G>,
        rndcomm: &[u8; 32],
        casting_token: &TokenValue,
    ) -> Result<CastResponse, BbError> {
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Req {
            ballot: Ballot<G>,
            rndcomm: String,
            casting_token: TokenValue,
        }
        let url = self.base_url.join("ballots")?;
        let response = self
            .client
            .post(url)
            .json(&Req {
                ballot: ballot.clone(),
                rndcomm: hex::encode(rndcomm),
                casting_token: casting_token.clone(),
            })
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(BbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(BbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(BbError::Json)
        } else {
            Err(BbError::Http(status, body))
        }
    }

    /// `POST /cai` - submit the CAI disclosure for a cast ballot (Sec. 3.8.4).
    pub async fn cai(
        &self,
        digest: &BallotDigest,
        disclosure: &DiscloseCAI<G>,
    ) -> Result<CaiResponse, BbError> {
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Req {
            digest: BallotDigest,
            disclosure: DiscloseCAI<G>,
        }
        let url = self.base_url.join("cai")?;
        let response = self
            .client
            .post(url)
            .json(&Req {
                digest: *digest,
                disclosure: disclosure.clone(),
            })
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(BbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(BbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(BbError::Json)
        } else {
            Err(BbError::Http(status, body))
        }
    }

    /// `GET /receipts/{digest}` - public receipt lookup.
    pub async fn receipt(&self, digest: &BallotDigest) -> Result<ReceiptResponse, BbError> {
        let url = self.base_url.join(&format!("receipts/{digest}"))?;
        let response = self
            .client
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(BbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(BbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(BbError::Json)
        } else {
            Err(BbError::Http(status, body))
        }
    }

    /// `GET /ballots` - release stored ballots (tally driver, service token).
    pub async fn ballots(
        &self,
        service_token: &SecretString,
    ) -> Result<Vec<BallotRecord<G>>, BbError> {
        let url = self.base_url.join("ballots")?;
        let response = self
            .client
            .get(url)
            .header(
                "Authorization",
                format!("Bearer {}", service_token.expose_secret()),
            )
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(BbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(BbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(BbError::Json)
        } else {
            Err(BbError::Http(status, body))
        }
    }
}

/// Errors from the BB client.
#[derive(Debug, thiserror::Error)]
pub enum BbError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
}
