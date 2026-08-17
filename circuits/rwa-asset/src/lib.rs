use std::collections::HashMap;

use circuit_account::{AccountError, apply_transfer};
use thiserror::Error;
use xc_primitives::{AccountEntry, Address};
use xc_storage::{AccountUpdates, StorageError};

#[derive(Error, Debug)]
pub enum RwaError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("account error: {0}")]
    Account(#[from] AccountError),
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
}

/// Mints `amount` into the issuer's own balance. `sender` must equal
/// `issuer` — issuance is self-minting, not a transfer of existing supply.
pub fn apply_issue(
    lookup: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    issuer: &Address,
    sender: &Address,
    nonce: u64,
    amount: u128,
) -> Result<AccountUpdates, RwaError> {
    if sender != issuer {
        return Err(RwaError::NotIssuer {
            issuer: issuer.clone(),
            sender: sender.clone(),
        });
    }

    let mut entry = lookup(sender)?.unwrap_or(AccountEntry {
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

    entry.balance += amount;
    entry.nonce += 1;

    let mut updates = HashMap::new();
    updates.insert(sender.clone(), entry);
    Ok(AccountUpdates(updates))
}

/// Transfer gated on both sender and recipient being KYC'd/allowlisted,
/// using the existing `AccountEntry.identity_hash` field as that marker.
/// The actual balance/nonce math is delegated to `circuit_account::apply_transfer`
/// once compliance is confirmed — proves circuits compose rather than each
/// reimplementing transfer math.
pub fn apply_compliant_transfer(
    lookup: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    sender: &Address,
    nonce: u64,
    to: &Address,
    amount: u128,
) -> Result<AccountUpdates, RwaError> {
    let sender_entry = lookup(sender)?;
    if !sender_entry.is_some_and(|e| e.identity_hash.is_some()) {
        return Err(RwaError::NotCompliant {
            address: sender.clone(),
        });
    }

    let to_entry = lookup(to)?;
    if !to_entry.is_some_and(|e| e.identity_hash.is_some()) {
        return Err(RwaError::NotCompliant {
            address: to.clone(),
        });
    }

    Ok(apply_transfer(lookup, sender, nonce, to, amount)?)
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
    fn issue_mints_only_for_issuer_and_rejects_others() {
        let db = temp_db();
        let issuer = addr(1);
        let other = addr(2);

        let updates = apply_issue(|a| db.get_account(a), &issuer, &issuer, 0, 1000).unwrap();
        assert_eq!(updates.0[&issuer].balance, 1000);

        let err = match apply_issue(|a| db.get_account(a), &issuer, &other, 0, 1000) {
            Err(err) => err,
            Ok(_) => panic!("expected NotIssuer error"),
        };
        assert!(matches!(err, RwaError::NotIssuer { .. }));
    }

    #[test]
    fn transfer_requires_both_parties_compliant() {
        let db = temp_db();
        let kyc_sender = addr(1);
        let kyc_recipient = addr(2);
        let non_kyc = addr(3);

        db.write_batch(&AccountUpdates(HashMap::from([
            (
                kyc_sender.clone(),
                AccountEntry {
                    balance: 100,
                    nonce: 0,
                    identity_hash: Some("kyc-1".into()),
                    zk_identity_verified: false,
                },
            ),
            (
                kyc_recipient.clone(),
                AccountEntry {
                    balance: 0,
                    nonce: 0,
                    identity_hash: Some("kyc-2".into()),
                    zk_identity_verified: false,
                },
            ),
            (
                non_kyc.clone(),
                AccountEntry {
                    balance: 0,
                    nonce: 0,
                    identity_hash: None,
                    zk_identity_verified: false,
                },
            ),
        ])))
        .unwrap();

        let updates = apply_compliant_transfer(
            |a| db.get_account(a),
            &kyc_sender,
            0,
            &kyc_recipient,
            40,
        )
        .unwrap();
        assert_eq!(updates.0[&kyc_recipient].balance, 40);

        let err = match apply_compliant_transfer(|a| db.get_account(a), &kyc_sender, 1, &non_kyc, 10)
        {
            Err(err) => err,
            Ok(_) => panic!("expected NotCompliant error"),
        };
        assert!(matches!(err, RwaError::NotCompliant { .. }));
    }
}
