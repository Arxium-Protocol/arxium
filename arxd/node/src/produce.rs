use crate::payload::{ActionPayload, ChainBlock, dispatch};
use anyhow::{Ok, Result};
use ed25519_dalek::SigningKey;
use xc_executor::execute_actions;
use xc_primitives::{Action, Address};
use xc_storage::{ArxiumDb, ValidatorSetSnapshot};

/// Build, execute, and store the next block using whatever actions are provided.
/// The stored block only lists the actions that were actually applied — see
/// `execute_actions` for why a subset can be dropped.
///
/// `proposer` is `Some((address, key))` when this node is a validator whose
/// turn it is to produce — the block gets signed. `None` keeps today's
/// unsigned-block behavior (solo/non-validator node).
pub fn produce_block(
    db: &ArxiumDb,
    actions: Vec<Action<ActionPayload>>,
    timestamp: u64,
    proposer: Option<(&Address, &SigningKey)>,
) -> Result<ChainBlock> {
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    let next_height = tip_height + 1;
    let parent: ChainBlock = db
        .get_block(tip_height)?
        .expect("tip block must exist if tip_height is set");

    // Pre-block set — matches `xc_executor::accept_block`'s
    // `get_validator_set_at(block.height)` exactly, so a self-produced block
    // and a gossiped/synced one fold JoinValidator/LeaveValidator the same way.
    let validators = db.get_validator_set_at(next_height)?;
    let (applied, account_updates, validator_changes) =
        execute_actions(db, actions, &validators, dispatch)?;

    let mut new_block = ChainBlock {
        height: next_height,
        parent_hash: parent.hash(),
        timestamp,
        actions: applied,
        proposer: None,
        signature: None,
    };
    if let Some((address, key)) = proposer {
        new_block.sign(address.clone(), key);
    }
    // One atomic write for the block record, the account changes it caused,
    // and (if any) the resulting validator-set change — a crash here must
    // never leave these disagreeing (e.g. nonces bumped with no block on
    // record for it, or vice versa).
    if validator_changes.is_empty() {
        db.write_batches(&[&account_updates, &new_block])?;
    } else {
        let snapshot = ValidatorSetSnapshot {
            effective_height: next_height + 1,
            validators: xc_executor::apply_validator_changes(validators, &validator_changes),
        };
        db.write_batches(&[&account_updates, &snapshot, &new_block])?;
    }

    Ok(new_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, Snapshot};

    #[test]
    fn produce_block_applies_transfer_and_advances_tip() {
        let dir =
            std::env::temp_dir().join(format!("arxium-test-produce-block-{}", std::process::id()));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let genesis: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _) =
            execute_actions(&db, genesis.actions.clone(), &[], dispatch).unwrap();
        db.write_batches(&[&genesis_updates, &genesis]).unwrap();

        let alice_key = SigningKey::from_bytes(&[1u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();

        let mut accounts = BTreeMap::new();
        accounts.insert(
            alice.clone(),
            AccountEntry {
                balance: 1000,
                nonce: 0,
                identity_hash: None,
            },
        );
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts,
            validators: BTreeMap::new(),
            boot_nodes: Vec::new(),
        })
        .unwrap();

        let mut transfer = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::Transfer {
                to: bob.clone(),
                amount: 400,
            },
        };
        let signature = alice_key.sign(&transfer.signing_bytes());
        transfer.signature = Some(hex::encode(signature.to_bytes()));

        let block = produce_block(&db, vec![transfer], 1, None).unwrap();

        assert_eq!(block.height, 1);
        assert_eq!(db.get_account(&alice).unwrap().unwrap().balance, 600);
        assert_eq!(db.get_account(&bob).unwrap().unwrap().balance, 400);

        std::fs::remove_dir_all(&dir).ok();
    }
}
