use anyhow::{Ok, Result};
use ed25519_dalek::SigningKey;
use xc_executor::execute_actions;
use xc_primitives::{Action, Address, Block};
use xc_storage::ArxiumDb;

/// Build, execute, and store the next block using whatever actions are provided.
/// The stored block only lists the actions that were actually applied — see
/// `execute_actions` for why a subset can be dropped.
///
/// `proposer` is `Some((address, key))` when this node is a validator whose
/// turn it is to produce — the block gets signed. `None` keeps today's
/// unsigned-block behavior (solo/non-validator node).
pub fn produce_block(
    db: &ArxiumDb,
    actions: Vec<Action>,
    timestamp: u64,
    proposer: Option<(&Address, &SigningKey)>,
) -> Result<Block> {
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    let parent = db
        .get_block(tip_height)?
        .expect("tip block must exist if tip_height is set");

    let applied = execute_actions(db, actions)?;

    let mut new_block = Block {
        height: tip_height + 1,
        parent_hash: parent.hash(),
        timestamp,
        actions: applied,
        proposer: None,
        signature: None,
    };
    if let Some((address, key)) = proposer {
        new_block.sign(address.clone(), key);
    }
    db.write_batch(&new_block)?;

    Ok(new_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, Action, ActionPayload, Address, Snapshot};

    #[test]
    fn produce_block_applies_transfer_and_advances_tip() {
        let dir =
            std::env::temp_dir().join(format!("arxium-test-produce-block-{}", std::process::id()));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let genesis = Block::genesis(0);
        execute_actions(&db, genesis.actions.clone()).unwrap();
        db.write_batch(&genesis).unwrap();

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
