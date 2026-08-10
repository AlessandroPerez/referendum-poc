//! Error types (style guide §03).
//!
//! `thiserror` enum for failures the caller (or the HTTP boundary) must handle
//! differently per variant; `anyhow` for unexpected errors that are only
//! reported. Errors are logged exactly once — where they are handled
//! (`IntoResponse`), never before propagation.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller-fixable validation failure → 400.
    #[error("{0}")]
    Validation(String),

    /// Missing or invalid credentials → 401.
    #[error("unauthorized")]
    Unauthorized,

    /// Authenticated but not allowed → 403.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Missing resource → 404.
    #[error("not found: {0}")]
    NotFound(String),

    /// Duplicate or conflicting operation → 409.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Unexpected internal failure → 500. Cause chain preserved via `anyhow`.
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn unexpected(err: impl Into<anyhow::Error>) -> Self {
        Self::Unexpected(err.into())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Validation(m) => (StatusCode::BAD_REQUEST, m.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            Self::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            // Logged here, at the handling boundary — and nowhere else (§03).
            Self::Unexpected(e) => {
                tracing::error!(error = ?e, "unexpected internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_maps_to_400() {
        let response = Error::validation("bad input").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unexpected_maps_to_500_without_leaking_details() {
        let response = Error::unexpected(anyhow::anyhow!("sensitive internals")).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must be readable");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert_eq!(body["error"], "internal server error");
        assert!(
            !body.to_string().contains("sensitive internals"),
            "internals must not leak into the response body"
        );
    }

    #[test]
    fn conflict_maps_to_409() {
        let response = Error::conflict("duplicate").into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
