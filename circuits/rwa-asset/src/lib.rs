// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{AccountKey, AssetBalanceKey, KvRead};
use xc_primitives::{AccountEntry, Address, Asset};
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
}

/// Mints `amount` of `asset` into the issuer's own balance. `sender` must
/// equal `asset.issuer` — issuance is self-minting, not a transfer of
/// existing supply. `asset` is caller-resolved (not looked up here) so this
/// stays agnostic to whether the caller backs it with a real registry
/// (`arxd/runtime`'s `RegisterAsset`/`meta:asset:{id}`) or a fixed in-memory
/// one (`examples/toy-chain`, which has no registry at all).
///
/// Mints into `AssetBalanceKey`, not `AccountEntry.balance` — that's the
/// whole point of the asset/native split: fees and staking (native balance)
/// never require KYC, only regulated-asset balances do. The sender's
/// `AccountEntry` is still touched, but only for its nonce.
pub fn apply_issue<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
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

    let mut entry = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
        zk_identity_verified: false,
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

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), entry)]));
    let assets = AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_id.clone(), sender.clone()),
        existing_balance + amount,
    )]));
    Ok((accounts, assets))
}

/// Transfers `amount` of `asset` from `sender` to `to`, gated on both
/// parties being KYC'd/allowlisted (`AccountEntry.identity_hash.is_some()`)
/// when `asset.compliance_required` — an asset registered with that flag
/// unset moves freely, same as the native token. Balance/nonce math mirrors
/// `circuit_account::apply_transfer` but against `AssetBalanceKey`, not
/// `AccountEntry.balance`.
pub fn apply_compliant_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    sender: &Address,
    nonce: u64,
    to: &Address,
    amount: u128,
) -> Result<(AccountUpdates, AssetBalanceUpdates), RwaError> {
    if asset.compliance_required {
        let sender_entry = view.get(&AccountKey(sender))?;
        if !sender_entry.is_some_and(|e| e.identity_hash.is_some()) {
            return Err(RwaError::NotCompliant { address: sender.clone() });
        }
        let to_entry = view.get(&AccountKey(to))?;
        if !to_entry.is_some_and(|e| e.identity_hash.is_some()) {
            return Err(RwaError::NotCompliant { address: to.clone() });
        }
    }

    let mut sender_account = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
        zk_identity_verified: false,
    });
    if nonce != sender_account.nonce {
        return Err(RwaError::InvalidNonce {
            sender: sender.clone(),
            expected: sender_account.nonce,
            got: nonce,
        });
    }
    sender_account.nonce += 1;

    let sender_balance = view
        .get(&AssetBalanceKey { asset_id: &asset.asset_id, owner: sender })?
        .unwrap_or(0);
    if sender_balance < amount {
        return Err(RwaError::InsufficientBalance {
            asset_id: asset.asset_id.clone(),
            sender: sender.clone(),
            balance: sender_balance,
            amount,
        });
    }

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), sender_account)]));

    // ponytail: self-transfer is balance-neutral (would otherwise read its
    // own not-yet-applied debit as the credit) — mirrors
    // `circuit_account::apply_transfer`'s same special case.
    if to == sender {
        return Ok((accounts, AssetBalanceUpdates(BTreeMap::new())));
    }

    let to_balance = view
        .get(&AssetBalanceKey { asset_id: &asset.asset_id, owner: to })?
        .unwrap_or(0);

    let assets = AssetBalanceUpdates(BTreeMap::from([
        ((asset.asset_id.clone(), sender.clone()), sender_balance - amount),
        ((asset.asset_id.clone(), to.clone()), to_balance + amount),
    ]));
    Ok((accounts, assets))
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
        let asset = Asset { asset_id: "gold".into(), issuer: issuer.clone(), compliance_required: true };

        let (accounts, assets) = apply_issue(&db, &asset, &issuer, 0, 1000).unwrap();
        assert_eq!(assets.0[&("gold".to_string(), issuer.clone())], 1000);
        assert_eq!(accounts.0[&issuer].balance, 0, "issue must not touch the native balance");
        assert_eq!(accounts.0[&issuer].nonce, 1);

        let err = apply_issue(&db, &asset, &other, 0, 1000).unwrap_err();
        assert!(matches!(err, RwaError::NotIssuer { .. }));
    }

    #[test]
    fn compliant_transfer_fails_without_recipient_attestation_and_succeeds_after() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let asset = Asset { asset_id: "gold".into(), issuer: issuer.clone(), compliance_required: true };

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            issuer.clone(),
            AccountEntry { balance: 0, nonce: 0, identity_hash: Some("kyc-issuer".into()), zk_identity_verified: false },
        )])))
        .unwrap();
        let (accounts, assets) = apply_issue(&db, &asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Recipient has no identity_hash yet — the demo: fails.
        let err = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 40).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }));

        // Attestor grants recipient an attestation — now it succeeds.
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            recipient.clone(),
            AccountEntry { balance: 0, nonce: 0, identity_hash: Some("kyc-recipient".into()), zk_identity_verified: false },
        )])))
        .unwrap();
        let (accounts, assets) = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 40).unwrap();
        assert_eq!(assets.0[&("gold".to_string(), recipient.clone())], 40);
        assert_eq!(assets.0[&("gold".to_string(), issuer.clone())], 60);
        assert_eq!(accounts.0[&issuer].nonce, 2);
    }

    #[test]
    fn transfer_of_a_non_compliance_required_asset_skips_the_kyc_check() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let asset = Asset { asset_id: "open".into(), issuer: issuer.clone(), compliance_required: false };

        let (accounts, assets) = apply_issue(&db, &asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        let (_, assets) = apply_compliant_transfer(&db, &asset, &issuer, 1, &recipient, 10).unwrap();
        assert_eq!(assets.0[&("open".to_string(), recipient)], 10);
    }
}
