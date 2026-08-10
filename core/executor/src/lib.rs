use std::collections::HashMap;
use thiserror::Error;
use tracing::warn;
use xc_primitives::{AccountEntry, Action, Address, SignatureError};
use xc_storage::{AccountUpdates, ArxiumDb, StorageError};

#[derive(Error, Debug)]
pub enum ExecutorError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("signature check failed: {0}")]
    Signature(#[from] SignatureError),
}

/// Applies each action to current state, in order, buffering every success
/// in memory (an overlay on top of the DB) so later actions in the same
/// batch see its effect (e.g. two transfers from the same sender at
/// consecutive nonces) without touching the DB at all. An action that fails
/// on its own (bad signature, or whatever `dispatch` rejects) is skipped and
/// logged rather than aborting the batch — one bad action must not block
/// valid actions from other senders. Returns the actions that were actually
/// applied, in order, plus the resulting account changes — unwritten. The
/// caller is responsible for committing these together with the block
/// record in one atomic write, so a crash can never leave block bookkeeping
/// and account state disagreeing.
///
/// `dispatch` is the chain-specific payload → circuit mapping — this
/// function only owns the generic loop mechanics (signature check, overlay
/// chaining, buffer-and-skip-on-error), not what any given payload variant
/// means. `P` is the chain's action payload type.
pub fn execute_actions<P>(
    db: &ArxiumDb,
    actions: Vec<Action<P>>,
    dispatch: impl Fn(
        &Action<P>,
        &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    ) -> anyhow::Result<AccountUpdates>,
) -> Result<(Vec<Action<P>>, AccountUpdates), ExecutorError>
where
    P: serde::Serialize,
{
    let mut applied = Vec::with_capacity(actions.len());
    let mut overlay = HashMap::new();

    for action in actions {
        if let Err(err) = action.verify_signature() {
            warn!("dropping action from {}: {err}", action.sender);
            continue;
        }

        let lookup = |addr: &Address| match overlay.get(addr) {
            Some(entry) => Ok(Some(entry).cloned()),
            None => db.get_account(addr),
        };

        match dispatch(&action, &lookup) {
            Ok(updates) => {
                overlay.extend(updates.0);
                applied.push(action);
            }
            Err(err) => warn!("dropping action from {}: {err}", action.sender),
        }
    }

    Ok((applied, AccountUpdates(overlay)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_account::apply_transfer;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum TestPayload {
        Transfer { to: Address, amount: u128 },
    }

    fn dispatch(
        action: &Action<TestPayload>,
        lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    ) -> anyhow::Result<AccountUpdates> {
        match &action.payload {
            TestPayload::Transfer { to, amount } => {
                Ok(apply_transfer(lookup, &action.sender, action.nonce, to, *amount)?)
            }
        }
    }

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
    ) -> Action<TestPayload> {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: TestPayload::Transfer {
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

        let (applied, updates) = execute_actions(&db, actions, dispatch).unwrap();
        assert_eq!(
            applied.len(),
            2,
            "both consecutive-nonce actions should apply"
        );

        // Not yet written — execute_actions only buffers; the caller commits.
        assert!(db.get_account(&bob).unwrap().is_none());

        db.write_batch(&updates).unwrap();

        let alice_after = db.get_account(&alice).unwrap().unwrap();
        assert_eq!(alice_after.balance, 50);
        assert_eq!(alice_after.nonce, 2);

        let bob_after = db.get_account(&bob).unwrap().unwrap();
        assert_eq!(bob_after.balance, 50);
    }
}
