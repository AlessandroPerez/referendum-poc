//! Typed HTTP client for the Notification Server (NS) service.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::domain::Vid;

/// Request body for `POST /register`.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest {
    pub vid: Vid,
    pub rid: String,
}

/// One notification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub rid: String,
    pub rt_id: String,
}

/// Response from `GET /notifications/:vid/:rid`.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationList {
    pub notifications: Vec<Notification>,
}

/// Client for the NS service.
#[derive(Clone, Debug)]
pub struct NsClient {
    client: Client,
    base_url: Url,
}

impl NsClient {
    pub fn new(client: Client, mut base_url: Url) -> Self {
        let path = base_url.path();
        if !path.ends_with('/') {
            base_url.set_path(&format!("{path}/"));
        }
        Self { client, base_url }
    }

    pub async fn register(&self, vid: Vid, rid: &str) -> Result<(), NsError> {
        let url = self.base_url.join("register")?;
        let response = self
            .client
            .post(url)
            .json(&RegisterRequest {
                vid,
                rid: rid.to_string(),
            })
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(NsError::Network)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(NsError::Http(
                response.status(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// `POST /notify` - an RT reports that a credential is ready for `(vid, rid)`.
    pub async fn notify(&self, vid: Vid, rid: &str, rt_id: &str) -> Result<(), NsError> {
        #[derive(Serialize)]
        struct NotifyRequest {
            vid: Vid,
            rid: String,
            rt_id: String,
        }
        let url = self.base_url.join("notify")?;
        let response = self
            .client
            .post(url)
            .json(&NotifyRequest {
                vid,
                rid: rid.to_string(),
                rt_id: rt_id.to_string(),
            })
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(NsError::Network)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(NsError::Http(
                response.status(),
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    pub async fn notifications(&self, vid: Vid, rid: &str) -> Result<NotificationList, NsError> {
        let url = self
            .base_url
            .join(&format!("notifications/{}/{rid}", vid.value()))?;
        let response = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(NsError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(NsError::Network)?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(NsError::Json)
        } else {
            Err(NsError::Http(status, body))
        }
    }
}

/// Errors from the NS client.
#[derive(Debug, thiserror::Error)]
pub enum NsError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid URL path: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
}
