// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `/admin/*` — gated on its own bearer token (`admin_token`), mounted only
//! when one is configured. Never shares `rpc_token`: a route that writes a
//! full DB copy to the node's disk shouldn't be reachable with the same
//! token every ordinary client uses to submit actions.

use super::*;

/// Bearer check for `/admin/*` against `admin_token`. Only ever mounted
/// when the token is set, so a missing token here is a wiring bug, not an
/// open door — it still fails closed.
pub(super) async fn admin_guard<P: Payload>(
    State(state): State<AppState<P>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_PATH.to_string(),
        |matched| matched.as_str().to_string(),
    );
    let authorized = state.admin_token.as_ref().is_some_and(|token| {
        let expected = format!("Bearer {token}");
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.len() == expected.len() && value.as_bytes().ct_eq(expected.as_bytes()).into()
            })
    });
    if !authorized {
        record_request(&path, StatusCode::UNAUTHORIZED);
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let response = next.run(req).await;
    record_request(&path, response.status());
    response
}

#[derive(serde::Deserialize)]
pub(super) struct CheckpointRequest {
    /// Server-local directory to write into. Must not already exist —
    /// RocksDB refuses to checkpoint into an existing path rather than merge.
    output: PathBuf,
}

#[derive(Serialize)]
pub(super) struct CheckpointResponse {
    /// Tip at the time of the request. The checkpoint is of the live DB and
    /// may include blocks past `finalized_height`; a restore from it plus a
    /// resync reconciles anything provisional.
    height: u64,
    finalized_height: Option<u64>,
    path: PathBuf,
}

/// `POST /admin/checkpoint {"output": "<path>"}` — a consistent RocksDB
/// checkpoint of the running node, without stopping it. Same primitive as
/// `arxd snapshot`, which needs the node stopped only because it opens a
/// second DB handle; from inside the process that constraint doesn't apply.
pub(super) async fn admin_checkpoint<P: Payload>(
    State(state): State<AppState<P>>,
    body: Result<Json<CheckpointRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::BadRequest(err.to_string()))?;
    if !body.output.is_absolute() {
        return Err(ApiError::BadRequest(
            "output must be an absolute path".to_string(),
        ));
    }
    if body.output.exists() {
        return Err(ApiError::Conflict("output path already exists".to_string()));
    }
    let height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let finalized_height = state.db.get_finalized_height().unwrap_or_default();
    let db = state.db.clone();
    let output = body.output.clone();
    // Hard-links the SSTs and copies the live WAL — file I/O proportional
    // to the WAL, so off the async runtime.
    let result = tokio::task::spawn_blocking(move || db.export_checkpoint(&output)).await;
    match result {
        Ok(Ok(())) => {
            info!(
                "wrote checkpoint at height {height} to {}",
                body.output.display()
            );
            Ok(Json(CheckpointResponse {
                height,
                finalized_height,
                path: body.output,
            })
            .into_response())
        }
        Ok(Err(err)) => {
            warn!("checkpoint to {} failed: {err}", body.output.display());
            Ok((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
        }
        Err(err) => Err(ApiError::internal(anyhow::anyhow!(
            "checkpoint task panicked: {err}"
        ))),
    }
}
