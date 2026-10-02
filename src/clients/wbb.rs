//! Typed client for the Sunlight WBB read/submit API .
//!
//! Implements the exact signing convention used by the WBB:
//!
//! ```text
//! signed_data = SHA256(data || entity_id || decimal(timestamp_ms))
//! signature   = Ed25519.sign(signed_data)
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::{interval, timeout};

/// A signed log entry as expected by `POST /submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntry {
    #[serde(with = "serde_bytes_base64")]
    pub data: Vec<u8>,
    pub timestamp: i64,
    pub entity_id: String,
    #[serde(with = "serde_bytes_base64")]
    pub signature: Vec<u8>,
}

impl SignedEntry {
    /// Check this entry's signature against `key`, the verifying key pinned
    /// for `self.entity_id` (the message is what the board verifies:
    /// SHA-256 over data, entity id and timestamp).
    pub fn verify(&self, key: &ed25519_dalek::VerifyingKey) -> bool {
        use ed25519_dalek::{Signature, Verifier as _};
        let message = entry_message(&self.data, &self.entity_id, self.timestamp);
        Signature::from_slice(&self.signature)
            .map(|sig| key.verify(&message, &sig).is_ok())
            .unwrap_or(false)
    }
}

/// The bytes an entry signature covers.
fn entry_message(data: &[u8], entity_id: &str, timestamp: i64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(entity_id.as_bytes());
    hasher.update(format!("{timestamp}").as_bytes());
    hasher.finalize().into()
}

/// One validator's BLS signature over a sequenced leaf (demo validators;
/// absent when the log has no validators configured).
#[derive(Debug, Clone, Deserialize)]
pub struct WbbValidation {
    pub validator_id: String,
    /// Base64 compressed BLS signature.
    pub signature: String,
}

/// One sequenced leaf returned by `GET /entries` or `GET /entries/{index}`.
#[derive(Debug, Clone, Deserialize)]
pub struct SequencedEntry {
    pub leaf_index: i64,
    pub timestamp: i64,
    pub entry: serde_json::Value,
    /// Hex Merkle leaf hash, as computed by the log.
    #[serde(default)]
    pub leaf_hash: Option<String>,
    /// Validator signatures collected so far, sorted by validator id.
    #[serde(default)]
    pub validations: Vec<WbbValidation>,
}

/// One sequenced leaf with the entry's EXACT bytes as served (not re-encoded):
/// the Merkle leaf hash is computed over those bytes.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSequencedEntry {
    pub leaf_index: i64,
    pub timestamp: i64,
    pub entry: Box<serde_json::value::RawValue>,
    /// Hex Merkle leaf hash as claimed by the board (cross-checked, never trusted).
    #[serde(default)]
    pub leaf_hash: Option<String>,
    #[serde(default)]
    pub validations: Vec<WbbValidation>,
}

/// `GET /entries` with exact entry bytes.
#[derive(Debug, Clone, Deserialize)]
pub struct RawEntriesResponse {
    pub count: usize,
    pub entries: Vec<RawSequencedEntry>,
    #[serde(default)]
    pub validators: Vec<String>,
}

/// Response from `GET /entries`.
#[derive(Debug, Clone, Deserialize)]
pub struct EntriesResponse {
    pub count: usize,
    pub entries: Vec<SequencedEntry>,
    /// Validator ids registered at the log (empty outside the demo).
    #[serde(default)]
    pub validators: Vec<String>,
}

/// Response from `GET /phase`.
#[derive(Debug, Clone, Deserialize)]
pub struct PhaseResponse {
    pub phase: String,
}

/// WBB client. Holds a pre-configured [`reqwest::Client`] so TLS roots and
/// timeouts are set up once (see `protocol::tls`).
#[derive(Clone, Debug)]
pub struct WbbClient {
    client: Client,
    base_url: Url,
}

impl WbbClient {
    /// Build a client for `base_url`. The URL must end in the log prefix
    /// (e.g. `https://localhost:8443/wbb`). A trailing slash is added if absent
    /// so relative path joins behave consistently.
    pub fn new(client: Client, mut base_url: Url) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self { client, base_url }
    }

    /// The board's base URL (with a trailing slash).
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Submit a signed entry. Returns the raw JSON response.
    pub async fn submit(&self, entry: &SignedEntry) -> Result<serde_json::Value, WbbError> {
        let url = self.base_url.join("submit")?;
        let response = self
            .client
            .post(url)
            .json(entry)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(WbbError::Json)
        } else {
            Err(WbbError::Http(status, body))
        }
    }

    /// Submit and poll `/entries` until the entry is included, up to `deadline`.
    ///
    /// Identification is best-effort: it looks for an entry whose `data` field
    /// matches the submitted `data` bytes. This is sufficient for the PoC
    /// harness; production code would track a content hash.
    pub async fn submit_and_wait(
        &self,
        entry: &SignedEntry,
        deadline: Duration,
    ) -> Result<SequencedEntry, WbbError> {
        let data_b64 = BASE64.encode(&entry.data);
        self.submit(entry).await?;

        let result = timeout(deadline, async {
            let mut ticker = interval(Duration::from_millis(50));
            loop {
                ticker.tick().await;
                if let Ok(entries) = self.entries().await {
                    if let Some(found) = entries.entries.iter().find(|e| {
                        e.entry
                            .get("data")
                            .and_then(|v| v.as_str())
                            .map(|s| s == data_b64)
                            .unwrap_or(false)
                    }) {
                        return Ok(found.clone());
                    }
                }
            }
        })
        .await;

        result.map_err(|_| WbbError::NotIncluded)?
    }

    /// `POST /validations` - a validator's BLS signature over one leaf.
    pub async fn submit_validation(
        &self,
        validator_id: &str,
        leaf_index: i64,
        signature: &[u8],
    ) -> Result<serde_json::Value, WbbError> {
        let url = self.base_url.join("validations")?;
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "validator_id": validator_id,
                "leaf_index": leaf_index,
                "signature": BASE64.encode(signature),
            }))
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(WbbError::Json)
        } else {
            Err(WbbError::Http(status, body))
        }
    }

    /// `GET /entries`, keeping every entry's exact bytes (for log verification).
    pub async fn entries_raw(&self) -> Result<RawEntriesResponse, WbbError> {
        let url = self.base_url.join("entries")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        if status == StatusCode::OK {
            serde_json::from_str(&body).map_err(WbbError::Json)
        } else {
            Err(WbbError::Http(status, body))
        }
    }

    /// `GET /entries`.
    pub async fn entries(&self) -> Result<EntriesResponse, WbbError> {
        let url = self.base_url.join("entries")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        if status == StatusCode::OK {
            serde_json::from_str(&body).map_err(WbbError::Json)
        } else {
            Err(WbbError::Http(status, body))
        }
    }

    /// `GET /entries/{index}`. Returns `None` on 404.
    pub async fn entry(&self, index: i64) -> Result<Option<SequencedEntry>, WbbError> {
        let url = self.base_url.join(&format!("entries/{index}"))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        match status {
            StatusCode::OK => serde_json::from_str(&body)
                .map(Some)
                .map_err(WbbError::Json),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(WbbError::Http(status, body)),
        }
    }

    /// `GET /phase`.
    pub async fn phase(&self) -> Result<String, WbbError> {
        let url = self.base_url.join("phase")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(WbbError::Network)?;
        if status == StatusCode::OK {
            let parsed: PhaseResponse = serde_json::from_str(&body).map_err(WbbError::Json)?;
            Ok(parsed.phase)
        } else {
            Err(WbbError::Http(status, body))
        }
    }

    /// `GET /health`. Returns true if the WBB reports healthy.
    pub async fn health(&self) -> Result<bool, WbbError> {
        let url = self.base_url.join("../health")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        Ok(response.status().is_success())
    }

    /// `GET /checkpoint`. Returns the raw signed checkpoint note.
    pub async fn checkpoint(&self) -> Result<Vec<u8>, WbbError> {
        let url = self.base_url.join("checkpoint")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(WbbError::Network)?;
        let status = response.status();
        let body = response.bytes().await.map_err(WbbError::Network)?;
        if status == StatusCode::OK {
            Ok(body.to_vec())
        } else {
            Err(WbbError::Http(
                status,
                String::from_utf8_lossy(&body).into_owned(),
            ))
        }
    }
}

/// Sign WBB entry data with an Ed25519 key.
///
/// Message: `SHA256(data || entity_id || decimal(timestamp_ms))`.
pub fn sign_entry(data: &[u8], entity_id: &str, timestamp: i64, key: &SigningKey) -> SignedEntry {
    let message = entry_message(data, entity_id, timestamp);
    let signature = key.sign(&message).to_bytes().to_vec();

    SignedEntry {
        data: data.to_vec(),
        timestamp,
        entity_id: entity_id.to_string(),
        signature,
    }
}

/// Errors from the WBB client.
#[derive(Debug, thiserror::Error)]
pub enum WbbError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
    #[error("entry was not included within the deadline")]
    NotIncluded,
}

mod serde_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn signature_is_deterministic_known_vector() {
        // Deterministic Ed25519 key from seed bytes.
        let mut rng = ChaCha20Rng::from_seed([0xabu8; 32]);
        let signing_key = SigningKey::generate(&mut rng);

        let entry = sign_entry(b"hello,wbb", "ER-1", 123456789, &signing_key);
        assert_eq!(entry.entity_id, "ER-1");
        assert_eq!(entry.timestamp, 123456789);
        assert_eq!(BASE64.encode(&entry.data), BASE64.encode(b"hello,wbb"));

        // Re-sign identical data and assert byte-for-byte equality.
        let entry2 = sign_entry(b"hello,wbb", "ER-1", 123456789, &signing_key);
        assert_eq!(entry.signature, entry2.signature);

        // Different entity_id -> different signature.
        let entry3 = sign_entry(b"hello,wbb", "ER-2", 123456789, &signing_key);
        assert_ne!(entry.signature, entry3.signature);
    }

    #[test]
    fn signed_entry_serializes_to_base64_fields() {
        let mut rng = ChaCha20Rng::from_seed([0xcdu8; 32]);
        let signing_key = SigningKey::generate(&mut rng);
        let entry = sign_entry(b"test-data", "RT-1", 42, &signing_key);

        let json = serde_json::to_value(&entry).unwrap();
        assert!(!json["data"].as_str().unwrap().is_empty());
        assert!(!json["signature"].as_str().unwrap().is_empty());
        assert_eq!(json["entity_id"], "RT-1");
        assert_eq!(json["timestamp"], 42);
    }
}
