// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `GET /blocks*`, `GET /actions/{signature}`, `GET /evidence*`,
//! `GET /search` — the chain's block/action history, fault evidence, and
//! the single guess-the-kind lookup endpoint.

use super::*;

/// Status of a submitted action: "pending" while it's still queued in the
/// mempool, "confirmed" once a block including it is on the chain, and
/// "dropped" with the executor's reason when this node drained it and
/// failed to apply it (bad nonce, insufficient balance…). The dropped
/// record is an in-memory ring on the mempool, so it survives until ~1k
/// later drops or a restart; after that the action is a 404 like one that
/// was never sent.
pub(super) async fn get_action_status<P: Payload>(
    State(state): State<AppState<P>>,
    Path(signature): Path<String>,
) -> Result<Response, ApiError> {
    {
        let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if mempool.contains_signature(&signature) {
            return Ok(Json(serde_json::json!({ "status": "pending" })).into_response());
        }
        if let Some(reason) = mempool.dropped_reason(&signature) {
            return Ok(Json(serde_json::json!({ "status": "dropped", "reason": reason })).into_response());
        }
    }

    let height = state.db.get_action_block_height(&signature)?.ok_or(ApiError::NotFound)?;
    let block = state.db.get_block::<P>(height)?.ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("action index points at missing block {height} for {signature}"))
    })?;
    let action = block
        .actions
        .iter()
        .find(|action| action.signature.as_deref() == Some(signature.as_str()))
        .ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!(
                "action index points at block {height} but action {signature} isn't in it"
            ))
        })?;

    Ok(Json(serde_json::json!({
        "status": "confirmed",
        "height": height,
        "block_hash": block.hash(),
        "sender": action.sender,
        "nonce": action.nonce,
    }))
    .into_response())
}

#[derive(serde::Deserialize)]
pub(super) struct BlockRangeQuery {
    pub(super) from: u64,
    pub(super) to: u64,
}

/// Bounded window of blocks. Heights are sequential with no gaps (single
/// proposer, no forks), so this is a per-height point-lookup loop capped at
/// `MAX_PAGE_SIZE`, not a scan.
/// Serializes a block with a `finalized` flag alongside its own fields.
///
/// Injected into the block's own JSON object rather than nesting the block
/// under a wrapper, so this stays additive: every existing consumer keeps
/// reading `height`, `hash`, `actions` exactly where they were, and clients
/// that don't know about `finalized` ignore it.
///
/// Checked per height rather than compared against a single watermark because
/// certificates are written as quorums complete, which is not necessarily in
/// height order — see `ArxiumDb::get_finalized_height`. A block below the
/// highest certified height is not automatically certified itself.
fn block_with_finality<P: Payload>(
    db: &ArxiumDb,
    block: &Block<P>,
) -> Result<serde_json::Value, StorageError> {
    let finalized = db.get_finality_record(block.height)?.is_some();
    let weight_used = db.get_block_weight(block.height)?;
    let mut value = serde_json::to_value(block).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("finalized".into(), serde_json::Value::Bool(finalized));
        // PoE `resources_used`: the metered weight this block carried.
        object.insert("weight_used".into(), serde_json::Value::from(weight_used));
    }
    Ok(value)
}

pub(super) async fn get_blocks<P: Payload>(
    State(state): State<AppState<P>>,
    Query(range): Query<BlockRangeQuery>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    if range.from > range.to {
        return Err(ApiError::BadRequest("from must be <= to".to_string()));
    }
    // One finality lookup per block. The range is already capped, so this
    // is bounded; a single watermark comparison would be cheaper but wrong
    // for the reason `block_with_finality` documents.
    let blocks = state.db.get_block_range::<P>(range.from, range.to)?;
    let annotated =
        blocks.iter().map(|block| block_with_finality(&state.db, block)).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(annotated))
}

pub(super) async fn get_block_by_height<P: Payload>(
    State(state): State<AppState<P>>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let block = state.db.get_block::<P>(height)?.ok_or(ApiError::NotFound)?;
    Ok(Json(block_with_finality(&state.db, &block)?))
}

pub(super) async fn get_block_by_hash<P: Payload>(
    State(state): State<AppState<P>>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Case/prefix are normalized before the lookup, not compared as raw
    // strings, so `/blocks/AABBCC...` finds the same block as
    // `/blocks/aabbcc...`. A string that isn't even a valid 32-byte hash
    // can't name any block, same as one that doesn't match.
    let Ok(hash) = hash.parse::<Hash32>() else {
        return Err(ApiError::NotFound);
    };
    let height = state.db.get_block_height_by_hash(&hash)?.ok_or(ApiError::NotFound)?;
    let block = state.db.get_block::<P>(height)?.ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("block_hash index points at missing block {height} for {hash}"))
    })?;
    Ok(Json(block_with_finality(&state.db, &block)?))
}

/// Lists the filenames `xc_evidence::write_equivocation_artifact` /
/// `write_disagreement_artifact` have written to `evidence_dir` — each one
/// an `EvidenceArtifact` an outside party can fetch via `GET /evidence/{id}`
/// and check with `arx-verify`, no shell access to the node required.
pub(super) async fn get_evidence_list<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Json<Vec<String>>, ApiError> {
    let entries = match std::fs::read_dir(&state.evidence_dir) {
        Ok(entries) => entries,
        // No evidence directory yet just means no faults observed so far.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Json(Vec::new())),
        Err(err) => return Err(ApiError::internal(err)),
    };

    let mut ids: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .collect();
    ids.sort();
    Ok(Json(ids))
}

/// Serves one evidence artifact's raw JSON by filename, as listed by
/// `GET /evidence`. `id` is a filename, not a path — reject anything that
/// could escape `evidence_dir` rather than trusting the caller.
pub(super) async fn get_evidence_by_id<P: Payload>(
    State(state): State<AppState<P>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(ApiError::BadRequest("invalid evidence id".to_string()));
    }
    let path = state.evidence_dir.join(&id);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(err) => Err(ApiError::internal(err)),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct SearchQuery {
    pub(super) q: String,
}

/// Single lookup endpoint so a client doesn't need to guess whether `q` is
/// a height, an address, or a block/action hash — tries each in turn.
pub(super) async fn search<P: Payload>(
    State(state): State<AppState<P>>,
    Query(SearchQuery { q }): Query<SearchQuery>,
) -> Response {
    if let Ok(height) = q.parse::<u64>()
        && matches!(state.db.get_block::<P>(height), Ok(Some(_))) {
            return Json(serde_json::json!({ "kind": "block", "height": height }))
                .into_response();
        }

    if let Ok(address) = Address::parse(&q) {
        return Json(serde_json::json!({ "kind": "account", "address": address }))
            .into_response();
    }

    if let Ok(hash) = q.parse::<Hash32>()
        && let Ok(Some(height)) = state.db.get_block_height_by_hash(&hash) {
            return Json(serde_json::json!({ "kind": "block", "height": height })).into_response();
        }

    if let Ok(Some(height)) = state.db.get_action_block_height(&q) {
        return Json(serde_json::json!({ "kind": "action", "signature": q, "height": height }))
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}
