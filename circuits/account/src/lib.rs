// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{AccountKey, KvRead};
use xc_primitives::{AccountEntry, Address};
use xc_storage::{AccountUpdates, StorageError};

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("invalid nonce for {sender}: expected {expected}, got {got}")]
    InvalidNonce {
        sender: Address,
        expected: u64,
        got: u64,
    },
    #[error("insufficient balance for {sender}: has {balance}, needs {amount}")]
    InsufficientBalance {
        sender: Address,
        balance: u128,
        amount: u128,
    },
}

/// Validates and applies a transfer of `amount` from `sender` (at `nonce`) to
/// `to` against current state. Returns the updated sender/receiver entries
/// without writing them — caller decides when to commit (so a whole block
/// can be batched together). Takes plain values rather than an `Action`
/// so any chain's payload shape can route into this without this crate
/// knowing about it. `lookup` resolves an address to its current account
/// state; the caller controls where that comes from (DB, or DB overlaid
/// with not-yet-committed changes from earlier actions in the same block —
/// see `xc_storage::BlockView`).
pub fn apply_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    sender: &Address,
    nonce: u64,
    to: &Address,
    amount: u128,
) -> Result<AccountUpdates, AccountError> {
    let mut sender_entry = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
        zk_identity_verified: false,
    });

    if nonce != sender_entry.nonce {
        return Err(AccountError::InvalidNonce {
            sender: sender.clone(),
            expected: sender_entry.nonce,
            got: nonce,
        });
    }

    if sender_entry.balance < amount {
        return Err(AccountError::InsufficientBalance {
            sender: sender.clone(),
            balance: sender_entry.balance,
            amount,
        });
    }

    // ponytail: self-transfer is balance-neutral (would otherwise overwrite
    // itself in `updates` and mint balance out of nowhere) — just bump nonce.
    if to == sender {
        sender_entry.nonce += 1;
        let mut updates = BTreeMap::new();
        updates.insert(sender.clone(), sender_entry);
        return Ok(AccountUpdates(updates));
    }

    let mut receiver_entry = view.get(&AccountKey(to))?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
        zk_identity_verified: false,
    });

    sender_entry.balance -= amount;
    sender_entry.nonce += 1;
    receiver_entry.balance += amount;

    let mut updates = BTreeMap::new();
    updates.insert(sender.clone(), sender_entry);
    updates.insert(to.clone(), receiver_entry);

    Ok(AccountUpdates(updates))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_storage::ArxiumDb;

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    // ponytail: nanos alone collide often enough under parallel test
    // execution to hit RocksDB's single-writer LOCK — the atomic counter
    // guarantees uniqueness even when two threads land on the same tick.
    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn addr() -> Address {
        Address::from_pubkey_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn self_transfer_is_balance_neutral_and_bumps_nonce() {
        let db = temp_db();
        let sender = addr();
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            sender.clone(),
            AccountEntry {
                balance: 100,
                nonce: 0,
                identity_hash: None,
                zk_identity_verified: false,
            },
        )])))
        .unwrap();

        let updates = apply_transfer(&db, &sender, 0, &sender, 30).unwrap();
        let entry = &updates.0[&sender];
        assert_eq!(entry.balance, 100, "self-transfer must not mint balance");
        assert_eq!(entry.nonce, 1, "self-transfer must still bump nonce");
    }
}
