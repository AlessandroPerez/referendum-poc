//! Public WBB page + same-origin read proxy (Sec. 3.8.5 manual verification).
//!
//! Serves the read-only bulletin-board web page from `static_dir` and proxies
//! the WBB read API so the browser needs no CORS or extra trust anchors:
//!   - `GET /api/entries`      - decoded entry table rows
//!   - `GET /api/entries/{i}`  - one raw sequenced entry
//!   - `GET /api/phase`        - current phase
//!   - `GET /api/checkpoint`   - signed checkpoint text

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
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
    let mut rows = Vec::with_capacity(entries.entries.len());
    for sequenced in entries.entries {
        let entity_ids: Vec<String> = sequenced
            .entry
            .get("entity_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let Some(data_b64) = sequenced.entry.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(data) = BASE64.decode(data_b64) else {
            continue;
        };
        let Some(parsed) = voting::parse_wbb_data(&data) else {
            continue;
        };
        let payload = parsed
            .decode_payload::<serde_json::Value>()
            .unwrap_or_else(|_| serde_json::Value::String(parsed.content.clone()));
        rows.push(EntryRow {
            leaf_index: sequenced.leaf_index,
            timestamp: sequenced.timestamp,
            phase: parsed.phase,
            role: parsed.role,
            entry_type: parsed.entry_type,
            threshold: parsed.threshold,
            entity_ids,
            payload,
        });
    }
    Ok(Json(rows))
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

pub fn router(state: Arc<WbbUiState>) -> Router {
    Router::new()
        .route("/api/entries", get(entries_handler))
        .route("/api/entries/:index", get(entry_handler))
        .route("/api/phase", get(phase_handler))
        .route("/api/checkpoint", get(checkpoint_handler))
        .fallback_service(ServeDir::new(&state.static_dir).append_index_html_on_directories(true))
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
