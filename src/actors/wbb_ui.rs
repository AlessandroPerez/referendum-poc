//! Public WBB page + same-origin read proxy (Sec. 3.8.5 manual verification).
//!
//! Serves the read-only bulletin-board web page from `static_dir` and proxies
//! the WBB read API so the browser needs no CORS or extra trust anchors:
//!   - `GET /api/entries`      - decoded entry table rows (with validator ids)
//!   - `GET /api/entries/{i}`  - one raw sequenced entry
//!   - `GET /api/phase`        - current phase
//!   - `GET /api/checkpoint`   - signed checkpoint text
//!   - `GET /api/validators`   - validator ids registered at the log

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Extension, Path},
    http::{header, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use tower_http::services::ServeDir;

use crate::actors::common::serve_rustls;
use crate::clients::wbb::WbbClient;
use crate::configuration::Settings;
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};
use crate::protocol::voting;

/// wbb-ui service state.
#[derive(Clone, Debug)]
pub struct WbbUiState {
    wbb_client: WbbClient,
    static_dir: PathBuf,
}

/// One decoded entry-table row for the public page.
#[derive(Debug, Serialize)]
struct EntryRow {
    leaf_index: i64,
    timestamp: i64,
    phase: String,
    role: String,
    entry_type: String,
    threshold: usize,
    entity_ids: Vec<String>,
    /// Decoded JSON payload for base64-JSON content fields, raw text otherwise.
    payload: serde_json::Value,
    /// For `ballot_digest` / `cast_intended_proof` entries: what the entry
    /// counts for, decided HERE with typed decoding - never in the browser
    /// from loosely typed JSON.
    ballot_box: Option<BallotBoxStatement>,
    /// Hex Merkle leaf hash reported by the log.
    leaf_hash: Option<String>,
    /// Validators that verified this leaf's Merkle inclusion and BLS-signed it.
    validations: Vec<String>,
    /// Number of validators registered at the log (0 outside the demo).
    validators_total: usize,
    /// For a `tally_result` entry: whether enough tabulation tellers really
    /// co-signed it. The page shows a result only when they did.
    tally_result_signed: bool,
}

/// What a `ballot_digest` or `cast_intended_proof` entry counts for.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum BallotBoxStatement {
    /// Well-formed and signed by the ballot box it names: counts.
    Valid { bb_id: u64, digest: String },
    /// Counts for nothing (unreadable, or names a ballot box that did not
    /// sign it) - shown as a warning. The audit WARNs and names the box.
    Ignored {
        reason: &'static str,
        /// The digest it claims to be about, if that much can be read.
        digest: Option<String>,
    },
}

fn ballot_box_statement(
    parsed: &voting::ParsedWbbData,
    entry: &serde_json::Value,
) -> Option<BallotBoxStatement> {
    let decoded = match parsed.entry_type.as_str() {
        "ballot_digest" => parsed
            .decode_payload::<voting::BallotDigestEntry>()
            .map(|p| (p.receipt.bb_id, p.digest)),
        "cast_intended_proof" => parsed
            .decode_payload::<voting::CaiEntry>()
            .map(|p| (p.bb_id, p.digest)),
        "ballot_metadata" => parsed
            .decode_payload::<voting::BallotMetadataEntry>()
            .map(|p| (p.bb_id, p.digest)),
        _ => return None,
    };
    Some(match decoded {
        Ok((bb_id, digest)) if voting::signed_by_ballot_box(entry, bb_id) => {
            BallotBoxStatement::Valid {
                bb_id,
                digest: digest.to_string(),
            }
        }
        Ok((_, digest)) => BallotBoxStatement::Ignored {
            reason: "it names a ballot box that did not sign it",
            digest: Some(digest.to_string()),
        },
        Err(_) => BallotBoxStatement::Ignored {
            reason: "it cannot be read",
            digest: parsed
                .decode_payload::<serde_json::Value>()
                .ok()
                .and_then(|v| v.get("digest")?.as_str().map(str::to_owned)),
        },
    })
}

#[tracing::instrument(skip(state))]
async fn entries_handler(
    Extension(state): Extension<Arc<WbbUiState>>,
) -> Result<Json<Vec<EntryRow>>, UiError> {
    let entries = state
        .wbb_client
        .entries()
        .await
        .map_err(|e| UiError::Upstream(e.to_string()))?;
    let validators_total = entries.validators.len();
    let mut rows = Vec::with_capacity(entries.entries.len());
    for sequenced in entries.entries {
        let entity_ids = voting::entry_signer_ids(&sequenced.entry);
        let Some(data_b64) = sequenced.entry.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(data) = BASE64.decode(data_b64) else {
            continue;
        };
        let Some(parsed) = voting::parse_wbb_data(&data) else {
            // A co-signature that reached the board after its entry was
            // published: the log stores `ref:N` plus a signature over the
            // data of leaf N. Shown, so the index has no silent gap.
            if let Some(reference) = String::from_utf8_lossy(&data).strip_prefix("ref:") {
                rows.push(EntryRow {
                    leaf_index: sequenced.leaf_index,
                    timestamp: sequenced.timestamp,
                    phase: String::new(),
                    role: String::new(),
                    entry_type: "late_co_signature".to_string(),
                    tally_result_signed: false,
                    threshold: 1,
                    entity_ids,
                    ballot_box: None,
                    payload: serde_json::json!({ "signs_entry": reference.trim() }),
                    leaf_hash: sequenced.leaf_hash,
                    validations: sequenced
                        .validations
                        .into_iter()
                        .map(|v| v.validator_id)
                        .collect(),
                    validators_total,
                });
            }
            continue;
        };
        let payload = parsed
            .decode_payload::<serde_json::Value>()
            .unwrap_or_else(|_| serde_json::Value::String(parsed.content.clone()));
        let ballot_box = ballot_box_statement(&parsed, &sequenced.entry);
        let tally_result_signed = parsed.entry_type == "tally_result"
            && voting::signed_by_tellers(&sequenced.entry, voting::RESULT_SIGNERS);
        rows.push(EntryRow {
            ballot_box,
            leaf_index: sequenced.leaf_index,
            timestamp: sequenced.timestamp,
            phase: parsed.phase,
            role: parsed.role,
            entry_type: parsed.entry_type,
            threshold: parsed.threshold,
            entity_ids,
            payload,
            leaf_hash: sequenced.leaf_hash,
            validations: sequenced
                .validations
                .into_iter()
                .map(|v| v.validator_id)
                .collect(),
            validators_total,
            tally_result_signed,
        });
    }
    Ok(Json(rows))
}

async fn validators_handler(
    Extension(state): Extension<Arc<WbbUiState>>,
) -> Result<Json<serde_json::Value>, UiError> {
    let entries = state
        .wbb_client
        .entries()
        .await
        .map_err(|e| UiError::Upstream(e.to_string()))?;
    Ok(Json(
        serde_json::json!({ "validators": entries.validators }),
    ))
}

async fn entry_handler(
    Extension(state): Extension<Arc<WbbUiState>>,
    Path(index): Path<i64>,
) -> Result<Json<serde_json::Value>, UiError> {
    let entry = state
        .wbb_client
        .entry(index)
        .await
        .map_err(|e| UiError::Upstream(e.to_string()))?;
    Ok(Json(match entry {
        Some(e) => serde_json::json!({
            "leaf_index": e.leaf_index,
            "timestamp": e.timestamp,
            "entry": e.entry,
        }),
        None => serde_json::Value::Null,
    }))
}

async fn phase_handler(
    Extension(state): Extension<Arc<WbbUiState>>,
) -> Result<Json<serde_json::Value>, UiError> {
    let phase = state
        .wbb_client
        .phase()
        .await
        .map_err(|e| UiError::Upstream(e.to_string()))?;
    Ok(Json(serde_json::json!({ "phase": phase })))
}

async fn checkpoint_handler(
    Extension(state): Extension<Arc<WbbUiState>>,
) -> Result<String, UiError> {
    let checkpoint = state
        .wbb_client
        .checkpoint()
        .await
        .map_err(|e| UiError::Upstream(e.to_string()))?;
    String::from_utf8(checkpoint).map_err(|e| UiError::Upstream(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
enum UiError {
    #[error("upstream WBB error: {0}")]
    Upstream(String),
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "wbb-ui upstream error");
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "bulletin board unavailable" })),
        )
            .into_response()
    }
}

/// The page polls live data and its script changes with the PoC: never let
/// the browser serve a stale copy of either.
async fn no_cache(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    // The page renders text written by election authorities: no inline or
    // foreign script may ever run in it.
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );
    response
}

pub fn router(state: Arc<WbbUiState>) -> Router {
    Router::new()
        .route("/api/entries", get(entries_handler))
        .route("/api/entries/:index", get(entry_handler))
        .route("/api/phase", get(phase_handler))
        .route("/api/checkpoint", get(checkpoint_handler))
        .route("/api/validators", get(validators_handler))
        .fallback_service(ServeDir::new(&state.static_dir).append_index_html_on_directories(true))
        .layer(middleware::map_response(no_cache))
        .layer(Extension(state))
}

/// Run the wbb-ui service.
pub async fn run(settings: Settings) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

pub async fn build_service(
    settings: Settings,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<WbbUiState>,
)> {
    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let client = reqwest_client_trusting_ca(&ca_pem)?;
    let wbb_client = WbbClient::new(
        client,
        reqwest::Url::parse(&settings.wbb.base_url)
            .map_err(|e| anyhow::anyhow!("invalid WBB URL: {e}"))?,
    );

    let state = Arc::new(WbbUiState {
        wbb_client,
        static_dir: PathBuf::from(&settings.wbb_ui.static_dir),
    });

    let addr: SocketAddr = format!("{}:{}", settings.service.host, settings.service.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid service address: {e}"))?;

    let cert_pem = tokio::fs::read_to_string(&settings.tls.cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS cert: {e}"))?;
    let key_pem = tokio::fs::read_to_string(&settings.tls.key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS key: {e}"))?;
    let rustls_config = rustls_config_for_service(&cert_pem, &key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

    Ok((addr, rustls_config, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row is classified HERE, from typed content and the signer rule -
    /// never in the browser from loosely typed JSON.
    #[test]
    fn a_digest_entry_counts_only_for_the_box_that_signed_it() {
        let payload = serde_json::json!({
            "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "emoji": ["a"],
            "public_pin_emoji": ["b"],
            "receipt": { "seq_no": 1, "received_at_unix_ms": 1, "bb_id": 1 },
        });
        let data = format!(
            "voting,BB,ballot_digest,1,{}",
            BASE64.encode(serde_json::to_string(&payload).unwrap())
        );
        let parsed = voting::parse_wbb_data(data.as_bytes()).unwrap();
        let statement = |entry: serde_json::Value| ballot_box_statement(&parsed, &entry).unwrap();

        assert!(matches!(
            statement(serde_json::json!({ "entity_id": "BB-1" })),
            BallotBoxStatement::Valid { bb_id: 1, .. }
        ));
        // Signed by the other box, or by nobody, or carrying both signer
        // forms (which the board would never verify as a whole).
        // A metadata entry carries an encrypted ballot-box id, which cannot
        // be built here; the live `wbb_ui_smoke` pins that classification on
        // real entries. What is checked here is that an unreadable one is
        // shown as ignored rather than skipped.
        let unreadable = {
            let data = format!(
                "voting,BB,ballot_metadata,1,{}",
                BASE64.encode(r#"{"digest":"x","bb_id":1}"#)
            );
            voting::parse_wbb_data(data.as_bytes()).unwrap()
        };
        assert!(matches!(
            ballot_box_statement(&unreadable, &serde_json::json!({ "entity_id": "BB-1" })),
            Some(BallotBoxStatement::Ignored { reason, .. }) if reason == "it cannot be read"
        ));

        for entry in [
            serde_json::json!({ "entity_id": "BB-2" }),
            serde_json::json!({ "entity_ids": ["BB-2"] }),
            serde_json::json!({ "entity_id": "BB-1", "entity_ids": ["BB-2"] }),
            serde_json::json!({ "entity_id": "BB-2", "entity_ids": ["BB-1"] }),
            serde_json::json!({}),
        ] {
            assert!(
                matches!(
                    statement(entry.clone()),
                    BallotBoxStatement::Ignored { reason, .. }
                        if reason == "it names a ballot box that did not sign it"
                ),
                "{entry} must not count for BB-1"
            );
        }

        // Unreadable content is shown as ignored, with the digest it claims.
        let broken = format!(
            "voting,BB,ballot_digest,1,{}",
            BASE64.encode(r#"{"digest":"zz","emoji":[]}"#)
        );
        let parsed = voting::parse_wbb_data(broken.as_bytes()).unwrap();
        assert!(matches!(
            ballot_box_statement(&parsed, &serde_json::json!({ "entity_id": "BB-1" })),
            Some(BallotBoxStatement::Ignored { reason, digest })
                if reason == "it cannot be read" && digest.as_deref() == Some("zz")
        ));
    }
}
