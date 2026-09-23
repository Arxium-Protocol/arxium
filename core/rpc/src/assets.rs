// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `GET /assets*` — the regulated-asset registry and its cap tables.

use super::*;

/// The trust anchor a client shows beside a symbol: whether the issuer holds
/// a live attestation. Symbols are not unique, so this — not the ticker — is
/// what tells two `GOLD`s apart in an interface. Same rule as
/// `circuit_rwa_asset::is_attested`.
pub(super) fn issuer_attested(db: &ArxiumDb, issuer: &Address) -> Result<bool, StorageError> {
    circuit_rwa_asset::is_attested(db, issuer)
}

pub(super) fn parse_ref(s: &str) -> Result<AssetRef, ApiError> {
    AssetRef::parse(s).map_err(|err| ApiError::BadRequest(err.to_string()))
}

/// One row of an asset's cap table: balance plus the issuer's freeze state.
#[derive(Serialize)]
pub(super) struct AssetHolderRow {
    address: Address,
    balance: u128,
    frozen: bool,
    frozen_amount: u128,
    attested_at: Option<u64>,
}

/// The cap table — every address with a non-zero balance (from the
/// `meta:asset_holders` index) with its balance and holder state.
pub(super) async fn get_asset_holders<P: Payload>(
    State(state): State<AppState<P>>,
    Path(asset_ref): Path<String>,
) -> Result<Json<Vec<AssetHolderRow>>, ApiError> {
    let asset_ref = parse_ref(&asset_ref)?;
    state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    let holders = state.db.get_asset_holders(&asset_ref)?;
    let mut rows = Vec::with_capacity(holders.len());
    for address in holders {
        let balance = state.db.get_asset_balance(&asset_ref, &address)?;
        let holder_state = state.db.get_holder_state(&asset_ref, &address)?;
        let attested_at = state
            .db
            .get_account(&address)?
            .and_then(|account| account.attested_at);
        rows.push(AssetHolderRow {
            address,
            balance,
            frozen: holder_state.frozen,
            frozen_amount: holder_state.frozen_amount,
            attested_at,
        });
    }
    Ok(Json(rows))
}

/// The registry record plus what a client needs to render it safely without
/// a second call: `holders` (the cap-table size) and `issuer_attested`. The
/// record's own `asset_ref` field is surfaced as `ref`.
#[derive(Serialize)]
pub(super) struct AssetResponse {
    #[serde(rename = "ref")]
    asset_ref: AssetRef,
    #[serde(flatten)]
    asset: Asset,
    issuer_attested: bool,
    holders: usize,
}

pub(super) fn asset_response(db: &ArxiumDb, asset: Asset) -> Result<AssetResponse, StorageError> {
    let holders = db.get_asset_holders(&asset.asset_ref)?.len();
    let issuer_attested = issuer_attested(db, &asset.issuer)?;
    Ok(AssetResponse {
        asset_ref: asset.asset_ref.clone(),
        asset,
        issuer_attested,
        holders,
    })
}

#[derive(serde::Deserialize)]
pub(super) struct AssetsQuery {
    /// Restrict the listing to one issuer's assets.
    pub(super) issuer: Option<String>,
}

/// Every asset registered on this chain, in registration order — or, with
/// `?issuer=`, just that issuer's.
pub(super) async fn get_assets<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<AssetsQuery>,
) -> Result<Json<Vec<AssetResponse>>, ApiError> {
    let issuer = query
        .issuer
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let assets = state.db.list_assets()?;
    let rows = assets
        .into_iter()
        .filter(|asset| issuer.as_ref().is_none_or(|issuer| &asset.issuer == issuer))
        .map(|asset| asset_response(&state.db, asset))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

/// One asset's registry record by ref — the canonical lookup.
pub(super) async fn get_asset<P: Payload>(
    State(state): State<AppState<P>>,
    Path(asset_ref): Path<String>,
) -> Result<Json<AssetResponse>, ApiError> {
    let asset_ref = parse_ref(&asset_ref)?;
    let asset = state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    Ok(Json(asset_response(&state.db, asset)?))
}

/// Slug resolution — "is this name taken?" for a register form. The ref is
/// a pure function of `(issuer, asset_id)`, so this derives it and looks the
/// record up; 404 means the slug is free for that issuer, and the response
/// body carries the ref the registration would produce.
pub(super) async fn get_asset_alias<P: Payload>(
    State(state): State<AppState<P>>,
    Path((issuer, asset_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let issuer = parse_address(&issuer)?;
    let asset_ref = AssetRef::derive(&issuer, &asset_id)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    match state.db.get_asset(&asset_ref)? {
        Some(asset) => Ok(Json(asset_response(&state.db, asset)?).into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ref": asset_ref })),
        )
            .into_response()),
    }
}
