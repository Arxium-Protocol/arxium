// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `GET /validators*`, `GET /attestors*`, `GET /finality`,
//! `GET /operators/{address}/validators` — the validator set, its finality
//! health, and the trust-spectrum attestor registry.

use super::*;

/// One row of `GET /attestors` — a registered KYC provider.
#[derive(serde::Serialize)]
pub(super) struct AttestorResponse {
    attestor: String,
    name: String,
    registered_at: u64,
}

/// Every attestor currently in the trust-spectrum registry.
pub(super) async fn get_attestors<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Json<Vec<AttestorResponse>>, ApiError> {
    Ok(Json(
        state
            .db
            .list_attestors()?
            .into_iter()
            .map(|(attestor, record)| AttestorResponse {
                attestor: attestor.to_string(),
                name: record.name,
                registered_at: record.registered_at,
            })
            .collect(),
    ))
}

/// One address's attestor registry record, if currently registered.
pub(super) async fn get_attestor<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<AttestorResponse>, ApiError> {
    let address = parse_address(&address)?;
    let record = state
        .db
        .get_attestor_record(&address)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(AttestorResponse {
        attestor: address.to_string(),
        name: record.name,
        registered_at: record.registered_at,
    }))
}

#[derive(serde::Deserialize)]
pub(super) struct ValidatorSetQuery {
    /// Historical height to answer for. Absent means the chain's tip.
    pub(super) height: Option<u64>,
}

/// The validator set, by default as of the chain's tip — the same set
/// `xc_executor::accept_block` would check the next block's proposer against.
///
/// `?height=N` answers for a past height instead. The snapshots have always
/// been persisted (`validator_set:{height}`, read back by
/// `get_validator_set_at`, which `arxd/finality` already relies on to tally
/// votes against the set that was live at the voted height) — they simply had
/// no route. Exposing them is what lets an external indexer compute validator
/// uptime: turns proposed over turns *owed* needs the set at each historical
/// height, and the denominator was unobtainable while this only answered for
/// the tip.
/// Finality status, and — when nothing is finalizing — enough to tell why.
///
/// A bare "latest finalized height" would report `null` both for a chain that
/// is simply young and for one structurally unable to finalize at all, which
/// is the failure this endpoint exists to surface: a validator only votes if
/// it has registered a BLS key, and nothing requires one. A set can be
/// perfectly healthy for block production and never reach quorum, with no
/// symptom beyond a `warn!` per dropped vote. Reporting the set size, how many
/// of them can actually vote, and the quorum those numbers imply makes that
/// visible in one request.
pub(super) async fn get_finality<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Response, ApiError> {
    let tip_height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let validators = state.db.get_validator_set_at(tip_height)?;

    let mut voters = 0usize;
    let mut keyed: Vec<&Address> = Vec::new();
    for validator in validators.keys() {
        if state.db.get_bls_pubkey(validator)?.is_some() {
            voters += 1;
            keyed.push(validator);
        }
    }
    // Quorum is by voting power, so what matters is how much of it can
    // actually sign — a keyless whale can block finality on its own.
    let voting_power_with_bls_key = signed_power(&validators, keyed);

    let finalized_height = state.db.get_finalized_height()?;
    let record = match finalized_height {
        Some(height) => state.db.get_finality_record(height)?,
        None => None,
    };
    let final_watermark = state.db.get_final_watermark()?;

    Ok(Json(serde_json::json!({
        // null rather than absent: a client must be able to tell "nothing has
        // finalized yet" from "this node is too old to have the field".
        "finalized_height": finalized_height,
        "finalized_hash": record.as_ref().map(|r| r.block_hash),
        "signers": record.as_ref().map(|r| r.signers.clone()),
        "tip_height": tip_height,
        // How far behind the tip finality is running. Growing steadily means
        // votes are being produced but not reaching quorum.
        "blocks_behind_tip": finalized_height.map(|h| tip_height.saturating_sub(h)),
        // Irreversibility floor, as opposed to `finalized_height`'s highest
        // certificate: everything at or below this is contiguously certified
        // and no node will roll it back.
        "final_watermark": final_watermark,
        "validators": validators.len(),
        "validators_with_bls_key": voters,
        "total_voting_power": TOTAL_VOTING_POWER,
        "voting_power_with_bls_key": voting_power_with_bls_key,
        // Voting power a certificate needs, out of `total_voting_power`.
        "quorum": QUORUM_POWER,
        // The whole point: false means no amount of waiting will finalize
        // anything, because not enough of the set's power can even vote.
        "quorum_reachable": voting_power_with_bls_key >= QUORUM_POWER,
    }))
    .into_response())
}

pub(super) async fn get_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Json<Vec<Address>>, ApiError> {
    let tip_height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;

    // Membership only, sorted — the shape Retracer's uptime view and the
    // proposer formula (`sorted(set)[height % len]`) consume. Weights are
    // on `/validators/power`.
    Ok(Json(state.db.validator_addresses_at(height)?))
}

/// `{address: voting_power}` for the set at `?height=` (default: tip) —
/// the units `GET /finality`'s `quorum` is measured in.
pub(super) async fn get_validator_power<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Json<BTreeMap<String, u32>>, ApiError> {
    let tip_height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;
    Ok(Json(
        state
            .db
            .get_validator_set_at(height)?
            .into_iter()
            .map(|(a, p)| (a.to_string(), p.0))
            .collect(),
    ))
}

/// One validator's standing: its `ValidatorStatus` (Active / Pending /
/// Jailed / Leaving / Tombstoned — the state the epoch hook and the fault
/// paths already keep, previously unreachable over RPC), its voting power
/// in the tip set (0 when not in it), whether a BLS key is registered, and
/// its operator if any. 404 for an address that never staked to join.
pub(super) async fn get_validator<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Response, ApiError> {
    let address = parse_address(&address)?;
    let status = state
        .db
        .get_validator_status(&address)?
        .ok_or(ApiError::NotFound)?;
    let tip = state.db.get_tip_height()?.unwrap_or(0);
    let voting_power = state
        .db
        .get_validator_set_at(tip)?
        .into_iter()
        .find(|(a, _)| a == &address)
        .map(|(_, p)| p.0)
        .unwrap_or(0);
    let bls = state.db.get_bls_pubkey(&address)?;
    let operator = state.db.get_operator(&address)?;
    Ok(Json(serde_json::json!({
        "address": address,
        "status": status,
        "voting_power": voting_power,
        "bls_registered": bls.is_some(),
        "operator": operator,
    }))
    .into_response())
}

/// Every validator address currently authorizing `address` to submit
/// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey` on its behalf (see
/// `ActionPayload::AuthorizeOperator`) — drives a "your validators" listing
/// for a delegated-management client.
pub(super) async fn get_operator_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<Address>>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(state.db.get_validators_for_operator(&address)?))
}
