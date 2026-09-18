// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `GET /accounts/{address}` and its sub-resources: stake, delegated stake,
//! BLS finality key, and regulated-asset balances.

use super::*;

pub(super) async fn get_account<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<xc_primitives::AccountEntry>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(
        state.db.get_account(&address)?.ok_or(ApiError::NotFound)?,
    ))
}

pub(super) async fn get_account_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<xc_primitives::StakeAllocation>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(
        state
            .db
            .get_stake_allocation(&address, &address)?
            .ok_or(ApiError::NotFound)?,
    ))
}

/// Every allocation `address` holds as master, one per validator, so a
/// wallet can list its delegations without keeping a local file of which
/// validators it ever staked to. Each row's `active_amount` and `unbonding`
/// (with `unlock_at_height`) are reported as stored; a fully returned
/// allocation is deleted on maturity (`resolve_due_unbonding`), so it is
/// simply absent here. Empty list, not 404, when there are none.
pub(super) async fn get_account_stakes<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<xc_primitives::StakeAllocation>>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(state.db.get_stake_allocations_by_master(&address)?))
}

/// A delegated stake allocation: `master` need not equal `validator` (unlike
/// `GET /accounts/{address}/stake`, the self-stake case) — this is how an
/// operator/app looks up how much it has staked on a validator's behalf.
pub(super) async fn get_delegated_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path((master, validator)): Path<(String, String)>,
) -> Result<Json<xc_primitives::StakeAllocation>, ApiError> {
    let master = parse_address(&master)?;
    let validator = parse_address(&validator)?;
    Ok(Json(
        state
            .db
            .get_stake_allocation(&master, &validator)?
            .ok_or(ApiError::NotFound)?,
    ))
}

/// Whether `address` has a BLS key registered for finality precommit voting
/// (`ActionPayload::RegisterBlsKey`) — a validator without one can be in the
/// validator set but its votes are silently dropped by `arxd/finality`.
pub(super) async fn get_account_bls_key<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Response, ApiError> {
    let address = parse_address(&address)?;

    let tip_height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;

    // Certificates must be checked against the key registered at their height.
    // Reading the current key after rotation would incorrectly reject an old
    // valid certificate or accept a forged historical one.
    let pubkey = state
        .db
        .get_bls_pubkey_at(&address, height)?
        .ok_or(ApiError::NotFound)?;
    // Hex, not the serde byte array: every JSON consumer (Explorer, Retracer)
    // expects the same `0x…` form as `voter_pubkey` in the fault report.
    Ok(
        Json(serde_json::json!({ "pubkey": format!("0x{}", hex::encode(pubkey.0)) }))
            .into_response(),
    )
}

/// One row of `GET /accounts/{address}/assets`.
///
/// Carries the registry fields alongside the balance rather than just the ref:
/// a wallet has to know whether an asset is compliance-gated before it can
/// tell the holder why a transfer would be refused, and making that a second
/// request per asset would put an N+1 on the one screen that lists them all.
///
/// `frozen` and `decimals` are here for the same reason as
/// `compliance_required`: a frozen asset refuses every transfer, so a wallet
/// that can't see the flag can only report the failure after the fact, and
/// `balance` is a raw integer that cannot be rendered at all without the
/// scale. `symbol`/`name` are what the wallet shows next to the truncated
/// `ref`; they identify nothing. The rest of the record (claims,
/// jurisdictions, supply) is only needed on an asset's own screen, which can
/// fetch `GET /assets/{ref}`. `transfer_eligible` means this holder can send
/// at least one base unit to an otherwise eligible recipient; recipient and
/// nonce checks necessarily happen when the transfer is submitted.
#[derive(serde::Serialize)]
pub(super) struct AccountAssetBalance {
    #[serde(rename = "ref")]
    asset_ref: AssetRef,
    asset_id: String,
    symbol: String,
    name: String,
    issuer: String,
    issuer_attested: bool,
    compliance_required: bool,
    frozen: bool,
    holder_frozen: bool,
    frozen_amount: u128,
    transfer_eligible: bool,
    eligibility_reason: &'static str,
    decimals: u8,
    balance: u128,
}

impl AccountAssetBalance {
    fn new(
        db: &ArxiumDb,
        address: &Address,
        asset: Asset,
        balance: u128,
    ) -> Result<Self, StorageError> {
        let issuer_attested = issuer_attested(db, &asset.issuer)?;
        let holder_state = db.get_holder_state(&asset.asset_ref, address)?;
        let eligibility = circuit_rwa_asset::transfer_eligibility(db, &asset, address, balance)?;
        Ok(Self {
            asset_ref: asset.asset_ref,
            asset_id: asset.asset_id,
            symbol: asset.symbol,
            name: asset.name,
            issuer: asset.issuer.to_string(),
            issuer_attested,
            compliance_required: asset.compliance_required,
            frozen: asset.frozen,
            holder_frozen: holder_state.frozen,
            frozen_amount: holder_state.frozen_amount,
            transfer_eligible: eligibility.is_eligible(),
            eligibility_reason: eligibility.reason(),
            decimals: asset.decimals,
            balance,
        })
    }
}

/// Every regulated asset `address` holds a balance row for.
///
/// Includes rows that have gone to zero — a balance row is never deleted, and
/// "you held this and now hold none" is a different statement from "you never
/// held this". Answered from the `meta:account_assets:` index; the balance
/// keys themselves are ordered `{asset_ref}:{owner}` and cannot be scanned by
/// owner.
pub(super) async fn get_account_assets<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<AccountAssetBalance>>, ApiError> {
    let address = parse_address(&address)?;
    let refs = state.db.get_account_assets(&address)?;

    let mut balances = Vec::with_capacity(refs.len());
    for asset_ref in refs {
        // Indexed but unregistered is impossible through the normal write
        // path (both rows land in one atomic batch), so skip rather than
        // fail the whole listing.
        let Some(asset) = state.db.get_asset(&asset_ref)? else {
            continue;
        };
        let balance = state.db.get_asset_balance(&asset_ref, &address)?;
        balances.push(AccountAssetBalance::new(
            &state.db, &address, asset, balance,
        )?);
    }

    Ok(Json(balances))
}

/// `address`'s balance of one asset. 404 when the asset was never registered,
/// which is a different answer from a registered asset held at zero — the
/// latter is a legitimate 200 with `balance: 0`.
pub(super) async fn get_account_asset_balance<P: Payload>(
    State(state): State<AppState<P>>,
    Path((address, asset_ref)): Path<(String, String)>,
) -> Result<Json<AccountAssetBalance>, ApiError> {
    let address = parse_address(&address)?;
    let asset_ref = parse_ref(&asset_ref)?;
    let asset = state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    let balance = state.db.get_asset_balance(&asset_ref, &address)?;
    Ok(Json(AccountAssetBalance::new(
        &state.db, &address, asset, balance,
    )?))
}
