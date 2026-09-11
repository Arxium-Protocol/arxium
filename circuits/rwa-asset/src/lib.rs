// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{AccountKey, AssetBalanceKey, KvRead};
use xc_primitives::{AccountEntry, Address, Asset, ClaimTopic, CountryCode};
use xc_storage::{AccountUpdates, AssetBalanceUpdates, StorageError};

#[derive(Error, Debug)]
pub enum RwaError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("only the issuer ({issuer}) may issue supply, got sender {sender}")]
    NotIssuer { issuer: Address, sender: Address },
    #[error("invalid nonce for {sender}: expected {expected}, got {got}")]
    InvalidNonce {
        sender: Address,
        expected: u64,
        got: u64,
    },
    #[error("compliance check failed: {address} is not KYC'd/allowlisted")]
    NotCompliant { address: Address },
    #[error("insufficient {asset_id} balance for {sender}: has {balance}, needs {amount}")]
    InsufficientBalance {
        asset_id: String,
        sender: Address,
        balance: u128,
        amount: u128,
    },
    #[error("issuing {amount} of {asset_id} would raise supply to {resulting}, over the cap of {cap}")]
    SupplyCapExceeded {
        asset_id: String,
        cap: u128,
        resulting: u128,
        amount: u128,
    },
    #[error("supply of {asset_id} would overflow u128")]
    SupplyOverflow { asset_id: String },
    #[error("{asset_id} is frozen: no transfers until it is unfrozen")]
    AssetFrozen { asset_id: String },
    #[error("{address} is missing the {topic:?} claim required by {asset_id}")]
    MissingClaim {
        asset_id: String,
        address: Address,
        topic: ClaimTopic,
    },
    #[error("{address}'s jurisdiction ({jurisdiction:?}) is not among those {asset_id} permits")]
    JurisdictionNotAllowed {
        asset_id: String,
        address: Address,
        jurisdiction: Option<CountryCode>,
    },
}

/// Whether one party may hold `asset`, checked identically for sender and
/// recipient — a transfer is only compliant if both ends are.
///
/// `required_claims` is authoritative when non-empty, and `compliance_required`
/// is the fallback for assets registered before claim topics existed. They are
/// deliberately not both applied: an asset listing topics has already said
/// something more specific than "must be attested", and requiring the bool as
/// well would make it impossible to express topic gating without it.
fn check_party<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    party: &Address,
) -> Result<(), RwaError> {
    let entry = view.get(&AccountKey(party))?;

    if !asset.required_claims.is_empty() {
        // An attested account is still the baseline: topics qualify an
        // attestation, they don't substitute for having one.
        if entry.as_ref().is_none_or(|e| e.identity_hash.is_none()) {
            return Err(RwaError::NotCompliant { address: party.clone() });
        }
        let held = entry.as_ref().map(|e| e.claims.as_slice()).unwrap_or_default();
        if let Some(missing) = asset.required_claims.iter().find(|t| !held.contains(t)) {
            return Err(RwaError::MissingClaim {
                asset_id: asset.asset_id.clone(),
                address: party.clone(),
                topic: missing.clone(),
            });
        }
    } else if asset.compliance_required
        && entry.as_ref().is_none_or(|e| e.identity_hash.is_none())
    {
        return Err(RwaError::NotCompliant { address: party.clone() });
    }

    // An unknown jurisdiction is rejected, not waved through: a restricted
    // asset can only be held where it is permitted, and "we don't know" is
    // not a permission.
    if let Some(allowed) = &asset.allowed_jurisdictions {
        let held = entry.as_ref().and_then(|e| e.jurisdiction.clone());
        if !held.as_ref().is_some_and(|code| allowed.contains(code)) {
            return Err(RwaError::JurisdictionNotAllowed {
                asset_id: asset.asset_id.clone(),
                address: party.clone(),
                jurisdiction: held,
            });
        }
    }
    Ok(())
}

/// Mints `amount` of `asset` into the issuer's own balance. `sender` must
/// equal `asset.issuer` — issuance is self-minting, not a transfer of
/// existing supply. `asset` is caller-resolved (not looked up here) so this
/// stays agnostic to whether the caller backs it with a real registry
/// (`arxd/runtime`'s `RegisterAsset`/`asset_record:{id}`) or a fixed in-memory
/// one (`examples/toy-chain`, which has no registry at all).
///
/// Mints into `AssetBalanceKey`, not `AccountEntry.balance` — that's the
/// whole point of the asset/native split: fees and staking (native balance)
/// never require KYC, only regulated-asset balances do. The sender's
/// `AccountEntry` is still touched, but only for its nonce.
///
/// Takes `asset` by `&mut` because `total_supply` is part of the asset record
/// and issuance is what moves it: returning the running total separately
/// would let a caller persist balances while forgetting the counter, and then
/// `max_supply` would never bind. Callers that keep a registry are expected
/// to write the mutated record back (`arxd/runtime`'s `issue_asset` puts it
/// through `BlockUpdates::asset_registration`); callers with a fixed
/// in-memory asset (`examples/toy-chain`) can simply drop it.
pub fn apply_issue<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    sender: &Address,
    nonce: u64,
    amount: u128,
) -> Result<(AccountUpdates, AssetBalanceUpdates), RwaError> {
    if sender != &asset.issuer {
        return Err(RwaError::NotIssuer {
            issuer: asset.issuer.clone(),
            sender: sender.clone(),
        });
    }

    // Checked before any balance math so a rejected issue leaves nothing
    // half-applied. Overflow is its own error rather than a saturating
    // clamp: silently minting less than asked for is worse than failing.
    let resulting = asset
        .total_supply
        .checked_add(amount)
        .ok_or_else(|| RwaError::SupplyOverflow { asset_id: asset.asset_id.clone() })?;
    if let Some(cap) = asset.max_supply
        && resulting > cap
    {
        return Err(RwaError::SupplyCapExceeded {
            asset_id: asset.asset_id.clone(),
            cap,
            resulting,
            amount,
        });
    }

    let mut entry = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        ..Default::default()
    });

    if nonce != entry.nonce {
        return Err(RwaError::InvalidNonce {
            sender: sender.clone(),
            expected: entry.nonce,
            got: nonce,
        });
    }
    entry.nonce += 1;

    let existing_balance = view
        .get(&AssetBalanceKey { asset_id: &asset.asset_id, owner: sender })?
        .unwrap_or(0);

    asset.total_supply = resulting;

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), entry)]));
    let assets = AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_id.clone(), sender.clone()),
        existing_balance + amount,
    )]));
    Ok((accounts, assets))
}

/// Transfers `amount` of `asset` from `sender` to `to`, gated on both parties
/// clearing `check_party` — claim topics and jurisdiction when the asset
/// specifies them, otherwise the older `compliance_required` KYC flag. An
/// asset that specifies neither moves freely, same as the native token.
/// Balance/nonce math mirrors `circuit_account::apply_transfer` but against
/// `AssetBalanceKey`, not `AccountEntry.balance`.
pub fn apply_compliant_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    sender: &Address,
    nonce: u64,
    to: &Address,
    amount: u128,
) -> Result<(AccountUpdates, AssetBalanceUpdates), RwaError> {
    // First gate, ahead of compliance and balance: a freeze is meant to stop
    // circulation outright, so it must not be bypassable by a transfer that
    // would have failed a later check anyway for a different reason.
    if asset.frozen {
        return Err(RwaError::AssetFrozen { asset_id: asset.asset_id.clone() });
    }

    check_party(view, asset, sender)?;
    check_party(view, asset, to)?;

    let mut sender_account = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        ..Default::default()
    });
    if nonce != sender_account.nonce {
        return Err(RwaError::InvalidNonce {
            sender: sender.clone(),
            expected: sender_account.nonce,
            got: nonce,
        });
    }
    sender_account.nonce += 1;

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), sender_account)]));
    let assets = apply_forced_transfer(view, asset, sender, to, amount)?;
    Ok((accounts, assets))
}

/// Moves `amount` of `asset` from `from` to `to` with no compliance, freeze or
/// nonce gate — only the balance check, so it can never mint.
///
/// This is deliberately the unchecked mover, and it is both the tail of
/// `apply_compliant_transfer` (which runs every gate before calling it) and
/// the whole of `ForcedTransfer`. `ForcedTransfer` exists for the cases
/// compliance cannot express — a court order, a sanctioned holder, a lost
/// key — where the holder cannot or must not sign, and where the recipient's
/// claims may well be the reason the transfer is being forced. Freeze is
/// likewise not a gate here: freezing an instrument is exactly when a
/// regulator most needs to be able to move it. Authorization is the caller's
/// job (the runtime restricts `ForcedTransfer` to the chain governor); this
/// function assumes it has already been established.
pub fn apply_forced_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, RwaError> {
    let from_balance = view
        .get(&AssetBalanceKey { asset_id: &asset.asset_id, owner: from })?
        .unwrap_or(0);
    if from_balance < amount {
        return Err(RwaError::InsufficientBalance {
            asset_id: asset.asset_id.clone(),
            sender: from.clone(),
            balance: from_balance,
            amount,
        });
    }

    // ponytail: self-transfer is balance-neutral (would otherwise read its
    // own not-yet-applied debit as the credit) — mirrors
    // `circuit_account::apply_transfer`'s same special case.
    if to == from {
        return Ok(AssetBalanceUpdates(BTreeMap::new()));
    }

    let to_balance = view
        .get(&AssetBalanceKey { asset_id: &asset.asset_id, owner: to })?
        .unwrap_or(0);

    Ok(AssetBalanceUpdates(BTreeMap::from([
        ((asset.asset_id.clone(), from.clone()), from_balance - amount),
        ((asset.asset_id.clone(), to.clone()), to_balance + amount),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_storage::ArxiumDb;

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-rwa-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn issue_mints_asset_balance_not_native_balance_and_rejects_non_issuers() {
        let db = temp_db();
        let issuer = addr(1);
        let other = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 1000).unwrap();
        assert_eq!(assets.0[&("gold".to_string(), issuer.clone())], 1000);
        assert_eq!(accounts.0[&issuer].balance, 0, "issue must not touch the native balance");
        assert_eq!(accounts.0[&issuer].nonce, 1);

        assert_eq!(asset.total_supply, 1000, "issuance tracks cumulative supply");

        let err = apply_issue(&db, &mut asset, &other, 0, 1000).unwrap_err();
        assert!(matches!(err, RwaError::NotIssuer { .. }));
    }

    #[test]
    fn compliant_transfer_fails_without_recipient_attestation_and_succeeds_after() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            issuer.clone(),
            AccountEntry { identity_hash: Some("kyc-issuer".into()), ..Default::default() },
        )])))
        .unwrap();
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Recipient has no identity_hash yet — the demo: fails.
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 40).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }));

        // Attestor grants recipient an attestation — now it succeeds.
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            recipient.clone(),
            AccountEntry { identity_hash: Some("kyc-recipient".into()), ..Default::default() },
        )])))
        .unwrap();
        let (accounts, assets) = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 40).unwrap();
        assert_eq!(assets.0[&("gold".to_string(), recipient.clone())], 40);
        assert_eq!(assets.0[&("gold".to_string(), issuer.clone())], 60);
        assert_eq!(accounts.0[&issuer].nonce, 2);
    }

    #[test]
    fn issue_respects_max_supply_across_repeated_issuance() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("capped", issuer.clone(), false);
        asset.max_supply = Some(100);

        // Two issues that together exactly reach the cap are both fine —
        // the check is on the running total, not per-action.
        apply_issue(&db, &mut asset, &issuer, 0, 60).unwrap();
        assert_eq!(asset.total_supply, 60);
        apply_issue(&db, &mut asset, &issuer, 0, 40).unwrap();
        assert_eq!(asset.total_supply, 100);

        // One more unit is over.
        let err = apply_issue(&db, &mut asset, &issuer, 0, 1).unwrap_err();
        assert!(
            matches!(&err, RwaError::SupplyCapExceeded { cap: 100, resulting: 101, .. }),
            "got: {err}"
        );
        assert_eq!(asset.total_supply, 100, "a rejected issue must not move the counter");
    }

    #[test]
    fn issue_rejects_a_supply_overflow_rather_than_wrapping() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("uncapped", issuer.clone(), false);
        asset.total_supply = u128::MAX - 1;

        let err = apply_issue(&db, &mut asset, &issuer, 0, 2).unwrap_err();
        assert!(matches!(err, RwaError::SupplyOverflow { .. }), "got: {err}");
        assert_eq!(asset.total_supply, u128::MAX - 1);
    }

    /// The freeze gate runs ahead of the compliance and balance checks, so it
    /// reports `AssetFrozen` even for a transfer that would also have failed
    /// for another reason — otherwise a frozen asset's error message would
    /// depend on which other check happened to trip first.
    #[test]
    fn a_frozen_asset_blocks_transfers_ahead_of_every_other_check() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        asset.frozen = true;
        // Un-KYC'd recipient *and* a wrong nonce *and* an over-balance amount:
        // still reports the freeze.
        let err = apply_compliant_transfer(&db, &asset, &issuer, 99, &recipient, 10_000).unwrap_err();
        assert!(matches!(err, RwaError::AssetFrozen { .. }), "got: {err}");

        asset.frozen = false;
        let err = apply_compliant_transfer(&db, &asset, &issuer, 99, &recipient, 10_000).unwrap_err();
        assert!(!matches!(err, RwaError::AssetFrozen { .. }), "unfrozen, so some other check should trip");
    }

    /// Issuance is deliberately still allowed while frozen — a freeze stops
    /// circulation, it does not seal the supply.
    #[test]
    fn a_frozen_asset_can_still_be_issued() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("gold", issuer.clone(), true);
        asset.frozen = true;

        apply_issue(&db, &mut asset, &issuer, 0, 50).unwrap();
        assert_eq!(asset.total_supply, 50);
    }

    /// Seeds an attested account with the given claim topics and jurisdiction.
    fn attest(db: &ArxiumDb, who: &Address, claims: &[ClaimTopic], jurisdiction: Option<&str>) {
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            who.clone(),
            AccountEntry {
                identity_hash: Some(format!("kyc-{who}")),
                claims: claims.to_vec(),
                jurisdiction: jurisdiction.map(str::to_string),
                ..Default::default()
            },
        )])))
        .unwrap();
    }

    /// Both ends of a transfer must carry every required topic — a compliant
    /// sender cannot push a restricted asset to an under-claimed recipient.
    #[test]
    fn required_claims_are_enforced_on_both_parties() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc, ClaimTopic::Accredited];

        attest(&db, &issuer, &[ClaimTopic::Kyc, ClaimTopic::Accredited], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Recipient is attested and KYC'd but not Accredited.
        attest(&db, &recipient, &[ClaimTopic::Kyc], None);
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap_err();
        assert!(
            matches!(&err, RwaError::MissingClaim { topic: ClaimTopic::Accredited, address, .. } if address == &recipient),
            "got: {err}"
        );

        attest(&db, &recipient, &[ClaimTopic::Kyc, ClaimTopic::Accredited], None);
        apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10)
            .expect("both parties now hold every required claim");
    }

    /// A forced transfer walks through every gate a compliant transfer stops
    /// at — freeze, claims, jurisdiction, and the holder's own signature —
    /// because the situations it exists for are exactly the ones compliance
    /// refuses. The one thing it cannot do is create supply.
    #[test]
    fn forced_transfer_ignores_freeze_and_claims_but_cannot_mint() {
        let db = temp_db();
        let issuer = addr(1);
        let seized_from = addr(2);
        let receiver = addr(3);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc, ClaimTopic::Accredited];
        asset.allowed_jurisdictions = Some(vec!["CH".into()]);

        attest(&db, &issuer, &[ClaimTopic::Kyc, ClaimTopic::Accredited], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        attest(&db, &seized_from, &[ClaimTopic::Kyc, ClaimTopic::Accredited], Some("CH"));
        let (accounts, assets) =
            apply_compliant_transfer(&db, &asset, &issuer, 1, &seized_from, 60).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Freeze the asset and leave the receiver with no attestation at all:
        // a compliant transfer has two independent reasons to refuse here.
        asset.frozen = true;
        let err = apply_compliant_transfer(&db, &asset, &seized_from, 1, &receiver, 60).unwrap_err();
        assert!(matches!(err, RwaError::AssetFrozen { .. }), "got: {err}");

        let moved = apply_forced_transfer(&db, &asset, &seized_from, &receiver, 60).unwrap();
        assert_eq!(moved.0[&("bond".to_string(), seized_from.clone())], 0);
        assert_eq!(moved.0[&("bond".to_string(), receiver.clone())], 60);

        // The balance check is the floor a governor cannot go under: forcing
        // more than the holder has would be minting by another name.
        let err = apply_forced_transfer(&db, &asset, &seized_from, &receiver, 61).unwrap_err();
        assert!(
            matches!(err, RwaError::InsufficientBalance { balance: 60, amount: 61, .. }),
            "got: {err}"
        );
    }

    /// Topics qualify an attestation rather than replacing it: holding the
    /// claims with no `identity_hash` is still not compliant.
    #[test]
    fn required_claims_still_need_an_underlying_attestation() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc];

        attest(&db, &issuer, &[ClaimTopic::Kyc], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            recipient.clone(),
            AccountEntry { claims: vec![ClaimTopic::Kyc], ..Default::default() },
        )])))
        .unwrap();
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "got: {err}");
    }

    /// A non-empty `required_claims` takes over from `compliance_required`
    /// rather than stacking with it, so an asset can gate on topics alone.
    #[test]
    fn required_claims_supersede_the_compliance_required_flag() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), false);
        asset.required_claims = vec![ClaimTopic::Aml];

        attest(&db, &issuer, &[ClaimTopic::Aml], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // `compliance_required` is false, but the topic list still binds.
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "got: {err}");

        attest(&db, &recipient, &[ClaimTopic::Aml], None);
        apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap();
    }

    /// An unknown jurisdiction is a rejection, not a pass — the interesting
    /// half of the restriction, since the permissive reading would silently
    /// let unattributed holders through.
    #[test]
    fn jurisdiction_restriction_rejects_both_disallowed_and_unknown() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("reit", issuer.clone(), true);
        asset.allowed_jurisdictions = Some(vec!["CH".into(), "DE".into()]);

        attest(&db, &issuer, &[], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Attested, but jurisdiction unknown.
        attest(&db, &recipient, &[], None);
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap_err();
        assert!(
            matches!(&err, RwaError::JurisdictionNotAllowed { jurisdiction: None, address, .. } if address == &recipient),
            "got: {err}"
        );

        // Known, but not permitted.
        attest(&db, &recipient, &[], Some("US"));
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap_err();
        assert!(
            matches!(&err, RwaError::JurisdictionNotAllowed { jurisdiction: Some(j), .. } if j == "US"),
            "got: {err}"
        );

        attest(&db, &recipient, &[], Some("DE"));
        apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap();
    }

    /// `Some(vec![])` means nobody may hold it, and is distinct from `None`.
    #[test]
    fn an_empty_jurisdiction_allowlist_permits_nobody() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("sealed", issuer.clone(), false);

        attest(&db, &issuer, &[], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        asset.allowed_jurisdictions = Some(Vec::new());
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &addr(2), 10).unwrap_err();
        assert!(matches!(err, RwaError::JurisdictionNotAllowed { .. }), "got: {err}");
    }

    #[test]
    fn transfer_of_a_non_compliance_required_asset_skips_the_kyc_check() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("open", issuer.clone(), false);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        let (_, assets) = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap();
        assert_eq!(assets.0[&("open".to_string(), recipient)], 10);
    }
}
