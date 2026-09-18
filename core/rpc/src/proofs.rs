// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `GET /accounts/{address}/proof`, `GET /validators/{address}/proof`,
//! `GET /accounts/{address}/assets/{asset_ref}/proof` — EIP-1186-shaped
//! state proofs against the *final* watermark, never the tip, plus enough
//! (block, finality certificate) for a party with no node to check one.

use super::*;

/// EIP-1186-shaped state proof: one key's value (or proven absence) under a
/// *certified* state root, plus everything a party with no node needs to
/// check it — the block whose `state_root` it is, and the finality
/// certificate over that block. `arx-verify state-proof` does the check.
///
/// Served against the final watermark, never the tip: a proof against a
/// provisional root is a proof of something a reorg can undo.
#[derive(Serialize)]
pub(super) struct StateProofResponse {
    /// The raw state key, as `xc_circuit::KeySpec::encode` produces it.
    key: String,
    /// Decoded value, or `null` for a non-inclusion proof.
    value: serde_json::Value,
    /// Compressed sibling path (`xc_artifact::StateProof`); `proof.value`
    /// is the exact bincode bytes the leaf commits to.
    proof: xc_artifact::StateProof,
    height: u64,
    state_root: String,
    block_hash: String,
    /// Inputs to the PoE commitment the certificate signs over, so a
    /// verifier can bind `state_root` to `finality.ep` without trusting
    /// this node: `ep = block_ep(parent_state_root, block.tx_root,
    /// state_root, weight_used)`.
    parent_state_root: String,
    weight_used: u64,
    block: serde_json::Value,
    /// `null` only on a chain that has not finalized anything yet (then
    /// `height` is genesis and the proof is against the genesis root).
    finality: Option<xc_storage::FinalityRecord>,
}

fn state_proof<P: Payload, K: xc_circuit::KeySpec>(
    db: &ArxiumDb,
    key: &K,
) -> Result<StateProofResponse, StorageError> {
    let height = db.get_final_watermark()?;
    let block: Block<P> = db.get_block(height)?.ok_or(StorageError::CorruptedMeta)?;
    let parent_state_root = if height == 0 {
        String::new()
    } else {
        db.get_block::<P>(height - 1)?
            .map(|b| b.state_root)
            .unwrap_or_default()
    };
    let raw_key = key.encode();
    let inclusion = db.prove(&raw_key, &block.state_root)?;
    let value = match &inclusion.value {
        Some(bytes) => {
            let (decoded, _): (K::Value, usize) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
            serde_json::to_value(decoded).unwrap_or(serde_json::Value::Null)
        }
        None => serde_json::Value::Null,
    };
    let proof = inclusion.into_state_proof();
    Ok(StateProofResponse {
        key: String::from_utf8_lossy(&raw_key).into_owned(),
        value,
        proof,
        height,
        state_root: block.state_root.clone(),
        block_hash: block.hash().to_string(),
        parent_state_root,
        weight_used: db.get_block_weight(height)?,
        block: serde_json::to_value(&block).unwrap_or(serde_json::Value::Null),
        finality: db.get_finality_record(height)?,
    })
}

fn state_proof_response<P: Payload, K: xc_circuit::KeySpec>(
    db: &ArxiumDb,
    key: &K,
) -> Result<Json<StateProofResponse>, ApiError> {
    Ok(Json(state_proof::<P, K>(db, key)?))
}

pub(super) async fn get_account_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    state_proof_response::<P, _>(&state.db, &xc_circuit::AccountKey(&address))
}

pub(super) async fn get_validator_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    state_proof_response::<P, _>(&state.db, &xc_circuit::ValidatorStatusKey(&address))
}

pub(super) async fn get_account_asset_balance_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path((address, asset_ref)): Path<(String, String)>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    let asset_ref = parse_ref(&asset_ref)?;
    state_proof_response::<P, _>(
        &state.db,
        &xc_circuit::AssetBalanceKey {
            asset: &asset_ref,
            owner: &address,
        },
    )
}
