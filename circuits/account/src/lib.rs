use std::collections::HashMap;

use thiserror::Error;
use xc_primitives::{AccountEntry, Action, ActionPayload, Address};
use xc_storage::{BatchWritable, StorageError};

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

/// A set of account changes to be written atomically.
pub struct AccountUpdates(pub HashMap<Address, AccountEntry>);

impl BatchWritable for AccountUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (address, entry) in &self.0 {
            let key = format!("account:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(entry, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}
/// Validates and applies a single Transfer action against current state.
/// Returns the updated sender/receiver entries without writing them —
/// caller decides when to commit (so a whole block can be batched together).
/// `lookup` resolves an address to its current account state; the caller
/// controls where that comes from (DB, or DB overlaid with not-yet-committed
/// changes from earlier actions in the same block).
pub fn apply_transfer(
    lookup: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    action: &Action,
) -> Result<AccountUpdates, AccountError> {
    let ActionPayload::Transfer { to, amount } = &action.payload;

    let mut sender_entry = lookup(&action.sender)?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
    });

    if action.nonce != sender_entry.nonce {
        return Err(AccountError::InvalidNonce {
            sender: action.sender.clone(),
            expected: sender_entry.nonce,
            got: action.nonce,
        });
    }

    if sender_entry.balance < *amount {
        return Err(AccountError::InsufficientBalance {
            sender: action.sender.clone(),
            balance: sender_entry.balance,
            amount: *amount,
        });
    }

    // ponytail: self-transfer is balance-neutral (would otherwise overwrite
    // itself in `updates` and mint balance out of nowhere) — just bump nonce.
    if *to == action.sender {
        sender_entry.nonce += 1;
        let mut updates = HashMap::new();
        updates.insert(action.sender.clone(), sender_entry);
        return Ok(AccountUpdates(updates));
    }

    let mut receiver_entry = lookup(to)?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
    });

    sender_entry.balance -= amount;
    sender_entry.nonce += 1;
    receiver_entry.balance += amount;

    let mut updates = HashMap::new();
    updates.insert(action.sender.clone(), sender_entry);
    updates.insert(to.clone(), receiver_entry);

    Ok(AccountUpdates(updates))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::Action;
    use xc_storage::ArxiumDb;

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn addr() -> Address {
        Address::from_pubkey_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn self_transfer_is_balance_neutral_and_bumps_nonce() {
        let db = temp_db();
        let sender = addr();
        db.write_batch(&AccountUpdates(HashMap::from([(
            sender.clone(),
            AccountEntry {
                balance: 100,
                nonce: 0,
                identity_hash: None,
            },
        )])))
        .unwrap();

        let action = Action {
            sender: sender.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::Transfer {
                to: sender.clone(),
                amount: 30,
            },
        };

        let updates = apply_transfer(|addr| db.get_account(addr), &action).unwrap();
        let entry = &updates.0[&sender];
        assert_eq!(entry.balance, 100, "self-transfer must not mint balance");
        assert_eq!(entry.nonce, 1, "self-transfer must still bump nonce");
    }
}
