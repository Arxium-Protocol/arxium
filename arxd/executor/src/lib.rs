use circuit_account::{AccountError, AccountUpdates, apply_transfer};
use std::collections::HashMap;
use thiserror::Error;
use tracing::warn;
use xc_primitives::{Action, ActionPayload, SignatureError};
use xc_storage::{ArxiumDb, StorageError};

#[derive(Error, Debug)]
pub enum ExecutorError {
    #[error("account circuit error: {0}")]
    Account(#[from] AccountError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("signature check failed: {0}")]
    Signature(#[from] SignatureError),
}

/// Applies each action to current state, in order, buffering every success
/// in memory (an overlay on top of the DB) so later actions in the same
/// batch see its effect (e.g. two transfers from the same sender at
/// consecutive nonces) without touching the DB until the whole block is
/// done. An action that fails on its own (bad signature, stale nonce,
/// insufficient balance) is skipped and logged rather than aborting the
/// batch — one bad action must not block valid actions from other senders.
/// The buffered changes are written in a single atomic batch at the end, so
/// a crash mid-block leaves either all of the block's effects applied or
/// none of them. Returns the actions that were actually applied, in order.
pub fn execute_actions(db: &ArxiumDb, actions: Vec<Action>) -> Result<Vec<Action>, ExecutorError> {
    let mut applied = Vec::with_capacity(actions.len());
    let mut overlay = HashMap::new();

    for action in actions {
        if let Err(err) = action.verify_signature() {
            warn!("dropping action from {}: {err}", action.sender);
            continue;
        }

        let lookup = |addr: &_| match overlay.get(addr) {
            Some(entry) => Ok(Some(entry).cloned()),
            None => db.get_account(addr),
        };

        let result = match &action.payload {
            ActionPayload::Transfer { .. } => apply_transfer(lookup, &action),
        };

        match result {
            Ok(updates) => {
                overlay.extend(updates.0);
                applied.push(action);
            }
            Err(err) => warn!("dropping action from {}: {err}", action.sender),
        }
    }

    db.write_batch(&AccountUpdates(overlay))?;

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use xc_primitives::{AccountEntry, Address};

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!(
            "arxium-test-executor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ArxiumDb::open(&path).unwrap()
    }

    fn signed_transfer(
        key: &SigningKey,
        sender: &Address,
        nonce: u64,
        to: &Address,
        amount: u128,
    ) -> Action {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: ActionPayload::Transfer {
                to: to.clone(),
                amount,
            },
        };
        let signature = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(signature.to_bytes()));
        action
    }

    #[test]
    fn same_block_actions_chain_and_commit_atomically() {
        let db = temp_db();
        let alice_key = SigningKey::from_bytes(&[3u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let bob = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();

        db.write_batch(&AccountUpdates(HashMap::from([(
            alice.clone(),
            AccountEntry {
                balance: 100,
                nonce: 0,
                identity_hash: None,
            },
        )])))
        .unwrap();

        // Two consecutive-nonce transfers from the same sender in one
        // batch: the second can only validate if it sees the first's
        // effect on alice's nonce/balance, which the DB alone won't show
        // until the whole batch is committed — proves the overlay works.
        let actions = vec![
            signed_transfer(&alice_key, &alice, 0, &bob, 40),
            signed_transfer(&alice_key, &alice, 1, &bob, 10),
        ];

        let applied = execute_actions(&db, actions).unwrap();
        assert_eq!(
            applied.len(),
            2,
            "both consecutive-nonce actions should apply"
        );

        let alice_after = db.get_account(&alice).unwrap().unwrap();
        assert_eq!(alice_after.balance, 50);
        assert_eq!(alice_after.nonce, 2);

        let bob_after = db.get_account(&bob).unwrap().unwrap();
        assert_eq!(bob_after.balance, 50);
    }
}
