//! Notification Server (NS) stub service.
//!
//! NS receives per-voter notifications from RTs and lets voter clients poll for
//! readiness. The PoC keeps notifications in memory.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::domain::Vid;
use crate::protocol::tls::rustls_config_for_service;

/// One notification record keyed by request id (`rid`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub rid: String,
    pub rt_id: String,
}

type NotificationsMap = HashMap<u64, HashMap<String, Vec<Notification>>>;

/// NS service state.
#[derive(Clone, Debug)]
pub struct NsState {
    #[allow(dead_code)]
    signing_key_seed: SecretString,
    /// Notifications grouped by vid and then by rid.
    notifications: Arc<Mutex<NotificationsMap>>,
}

impl NsState {
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            notifications: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new (vid, rid) pair. Returns true if it was newly created.
    pub async fn register(&self, vid: Vid, rid: String) -> bool {
        let mut map = self.notifications.lock().await;
        map.entry(vid.value())
            .or_default()
            .insert(rid, Vec::new())
            .is_none()
    }

    /// Add a notification for (vid, rid) from a specific RT.
    pub async fn notify(&self, vid: Vid, rid: String, notification: Notification) {
        let mut map = self.notifications.lock().await;
        if let Some(by_rid) = map.get_mut(&vid.value()) {
            if let Some(list) = by_rid.get_mut(&rid) {
                list.push(notification);
            }
        }
    }

    /// Return the list of notifications for (vid, rid).
    pub async fn notifications_for(&self, vid: Vid, rid: &str) -> Vec<Notification> {
        let map = self.notifications.lock().await;
        map.get(&vid.value())
            .and_then(|by_rid| by_rid.get(rid))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    vid: u64,
    rid: String,
}

#[derive(Debug, Deserialize)]
struct NotifyRequest {
    vid: u64,
    rid: String,
    rt_id: String,
}

#[derive(Debug, Serialize)]
struct NotificationList {
    notifications: Vec<Notification>,
}

async fn register_handler(
    Extension(state): Extension<Arc<NsState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, NsError> {
    let vid = Vid::new(req.vid).map_err(|_| NsError::BadRequest("invalid vid".to_string()))?;
    if state.register(vid, req.rid).await {
        Ok(StatusCode::CREATED)
    } else {
        Ok(StatusCode::OK)
    }
}

async fn notify_handler(
    Extension(state): Extension<Arc<NsState>>,
    Json(req): Json<NotifyRequest>,
) -> Result<StatusCode, NsError> {
    let vid = Vid::new(req.vid).map_err(|_| NsError::BadRequest("invalid vid".to_string()))?;
    let rid = req.rid.clone();
    state
        .notify(
            vid,
            rid.clone(),
            Notification {
                rid,
                rt_id: req.rt_id,
            },
        )
        .await;
    Ok(StatusCode::OK)
}

async fn poll_handler(
    Extension(state): Extension<Arc<NsState>>,
    Path((vid, rid)): Path<(u64, String)>,
) -> Result<Json<NotificationList>, NsError> {
    let vid = Vid::new(vid).map_err(|_| NsError::BadRequest("invalid vid".to_string()))?;
    let notifications = state.notifications_for(vid, &rid).await;
    Ok(Json(NotificationList { notifications }))
}

#[derive(Debug, thiserror::Error)]
enum NsError {
    #[error("bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for NsError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: Arc<NsState>) -> Router {
    with_state(
        health_router()
            .route("/register", post(register_handler))
            .route("/notify", post(notify_handler))
            .route("/notifications/:vid/:rid", get(poll_handler)),
        state,
    )
}

/// Run the NS service from settings and a signing key.
pub async fn run(settings: Settings, signing_key: SigningKey) -> anyhow::Result<()> {
    let state = Arc::new(NsState::new(signing_key));

    let addr: SocketAddr = format!("{}:{}", settings.service.host, settings.service.port)
        .parse()
        .expect("valid service address");

    let cert_pem = tokio::fs::read_to_string(&settings.tls.cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS cert: {e}"))?;
    let key_pem = tokio::fs::read_to_string(&settings.tls.key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS key: {e}"))?;
    let rustls_config = rustls_config_for_service(&cert_pem, &key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

    serve_rustls(router(state), addr, rustls_config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_key() -> SigningKey {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        SigningKey::generate(&mut rng)
    }

    #[tokio::test]
    async fn register_and_poll() {
        let state = NsState::new(test_key());

        let vid = Vid::new(1).unwrap();
        let rid = "rid-1".to_string();
        assert!(state.register(vid, rid.clone()).await);
        assert!(!state.register(vid, rid.clone()).await);

        state
            .notify(
                vid,
                rid.clone(),
                Notification {
                    rid: rid.clone(),
                    rt_id: "RT-1".to_string(),
                },
            )
            .await;

        let list = state.notifications_for(vid, &rid).await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].rt_id, "RT-1");
    }
}
