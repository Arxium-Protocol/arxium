// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Every fallible RPC handler's error type, and the one place a 500 gets
//! logged. The pattern this replaces — `Err(_) => StatusCode::INTERNAL_SERVER_ERROR`,
//! repeated across most handlers — threw away the actual `StorageError` at
//! the point it happened, so a node returning 500 in production gave no way
//! to find out why. A handler using `?` on `ApiError` can no longer forget
//! to log: `IntoResponse` below does it once, for every handler, instead of
//! each one remembering to `warn!` before returning.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::warn;
use xc_storage::StorageError;

pub enum ApiError {
    BadRequest(String),
    NotFound,
    Conflict(String),
    /// The chain hasn't produced its first block yet (no tip/genesis row).
    /// Distinct from `NotFound`: nothing is missing, the node just isn't
    /// ready.
    ServiceUnavailable,
    /// A storage error, or any other internal invariant violation
    /// (corrupted index, malformed on-disk data, a background task
    /// panicking). Logged here at the point it's converted, then reported
    /// to the client as a bare 500 with no body — the detail is for the
    /// node's own logs, never the response.
    Internal(anyhow::Error),
}

impl ApiError {
    /// For an error type this module has no direct `From` impl for (a
    /// handler-local one-off — bincode decode, filesystem I/O — rather than
    /// the common `StorageError` path).
    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        ApiError::Internal(err.into())
    }
}

impl From<StorageError> for ApiError {
    fn from(err: StorageError) -> Self {
        ApiError::Internal(err.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            ApiError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg).into_response(),
            ApiError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            ApiError::Internal(err) => {
                warn!("RPC handler failed: {err:#}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
