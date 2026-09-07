//! Typed HTTP client for the Tabulation Teller (TT) service (M4 signing,
//! M8 threshold tally).

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_group::serde::ScalarHelper;
use evoting::api::prelude::{
    CredentialControlProof, EncrChoice, VerifiableFingerprints, VerifiablePartialDecryption, Vote,
    ZetaVssBroadcast,
};
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

type G = RistrettoGroup;

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

/// Response from `GET /status`.
#[derive(Debug, Clone, Deserialize)]
pub struct StatusResponse {
    pub entity_id: String,
    pub status: String,
}

/// Client for one TT server.
#[derive(Clone, Debug)]
pub struct TtClient {
    client: Client,
    base_url: Url,
    token: SecretString,
}

impl TtClient {
    /// Build a client for `base_url` with the service bearer token required by
    /// `POST /sign`.
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

    /// `POST /sign` — ask the TT to sign a WBB data string.
    pub async fn sign(&self, data: &str, timestamp: i64) -> Result<SignResponse, TtError> {
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
            .map_err(TtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(TtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(TtError::Json)
        } else {
            Err(TtError::Http(status, body))
        }
    }

    /// Convert a [`SignResponse`] into a [`crate::clients::wbb::SignedEntry`].
    pub fn to_signed_entry(
        data: &str,
        response: &SignResponse,
    ) -> Result<crate::clients::wbb::SignedEntry, TtError> {
        use ed25519_dalek::Signature;
        let signature = BASE64
            .decode(&response.signature)
            .map_err(TtError::Base64)?;
        let bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| TtError::InvalidSignature)?;
        let signature = Signature::from_bytes(&bytes);
        Ok(crate::clients::wbb::SignedEntry {
            data: data.as_bytes().to_vec(),
            timestamp: response.timestamp,
            entity_id: response.entity_id.clone(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Shared plumbing for the authenticated JSON POST endpoints (M8).
    async fn post_json<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, TtError> {
        let url = self.base_url.join(path)?;
        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth_header())
            .json(body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(TtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(TtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(TtError::Json)
        } else {
            Err(TtError::Http(status, body))
        }
    }

    /// `POST /vss/zeta/round1` — open a ζ VSS session (§3.9 step 6).
    pub async fn zeta_round1(&self, session: &str) -> Result<ZetaVssBroadcast<G>, TtError> {
        self.post_json(
            "vss/zeta/round1",
            &serde_json::json!({ "session": session }),
        )
        .await
    }

    /// `POST /vss/zeta/combine` — combine broadcasts into this party's
    /// sub-share (§3.9 step 6); consumes the session.
    pub async fn zeta_combine(
        &self,
        session: &str,
        broadcasts: &[ZetaVssBroadcast<G>],
    ) -> Result<(usize, <G as GroupScalar>::Scalar), TtError> {
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Request<'a> {
            session: &'a str,
            broadcasts: &'a [ZetaVssBroadcast<G>],
        }
        #[derive(Deserialize)]
        struct Response {
            id: usize,
            #[serde(with = "ScalarHelper::<G>")]
            sub_share: <G as GroupScalar>::Scalar,
        }
        let response: Response = self
            .post_json(
                "vss/zeta/combine",
                &Request {
                    session,
                    broadcasts,
                },
            )
            .await?;
        Ok((response.id, response.sub_share))
    }

    /// `POST /decrypt/ox` — per-party ox-fingerprint decryptions.
    pub async fn decrypt_ox(
        &self,
        fps: &VerifiableFingerprints<G>,
    ) -> Result<Vec<VerifiablePartialDecryption<G>>, TtError> {
        self.post_json("decrypt/ox", &serde_json::json!({ "fps": fps }))
            .await
    }

    /// `POST /decrypt/acc-checks` — per-party ACC-check decryptions.
    pub async fn decrypt_acc_checks(
        &self,
        votes: &[Vote<G>],
        controls: &[CredentialControlProof<G>],
        zeta: <G as GroupScalar>::Scalar,
    ) -> Result<Vec<VerifiablePartialDecryption<G>>, TtError> {
        #[derive(Serialize)]
        #[serde(bound = "")]
        struct Request<'a> {
            votes: &'a [Vote<G>],
            controls: &'a [CredentialControlProof<G>],
            #[serde(with = "ScalarHelper::<G>")]
            zeta: <G as GroupScalar>::Scalar,
        }
        self.post_json(
            "decrypt/acc-checks",
            &Request {
                votes,
                controls,
                zeta,
            },
        )
        .await
    }

    /// `POST /decrypt/fps` — per-party credential-fingerprint decryptions.
    pub async fn decrypt_fps(
        &self,
        fps: &VerifiableFingerprints<G>,
    ) -> Result<
        (
            Vec<VerifiablePartialDecryption<G>>,
            Vec<VerifiablePartialDecryption<G>>,
        ),
        TtError,
    > {
        #[derive(Deserialize)]
        #[serde(bound = "")]
        struct Response {
            pub_fps: Vec<VerifiablePartialDecryption<G>>,
            vote_fps: Vec<VerifiablePartialDecryption<G>>,
        }
        let response: Response = self
            .post_json("decrypt/fps", &serde_json::json!({ "fps": fps }))
            .await?;
        Ok((response.pub_fps, response.vote_fps))
    }

    /// `POST /decrypt/tally` — per-party tally decryptions.
    #[allow(clippy::type_complexity)]
    pub async fn decrypt_tally(
        &self,
        enc_tally: &EncrChoice<G>,
    ) -> Result<
        (
            Vec<VerifiablePartialDecryption<G>>,
            Vec<Vec<VerifiablePartialDecryption<G>>>,
        ),
        TtError,
    > {
        #[derive(Deserialize)]
        #[serde(bound = "")]
        struct Response {
            l1: Vec<VerifiablePartialDecryption<G>>,
            l2: Vec<Vec<VerifiablePartialDecryption<G>>>,
        }
        let response: Response = self
            .post_json(
                "decrypt/tally",
                &serde_json::json!({ "enc_tally": enc_tally }),
            )
            .await?;
        Ok((response.l1, response.l2))
    }

    /// `GET /status`.
    pub async fn status(&self) -> Result<StatusResponse, TtError> {
        let url = self.base_url.join("status")?;
        let response = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(TtError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(TtError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(TtError::Json)
        } else {
            Err(TtError::Http(status, body))
        }
    }
}

/// Errors from the TT client.
#[derive(Debug, thiserror::Error)]
pub enum TtError {
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
