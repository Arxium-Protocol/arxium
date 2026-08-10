//! Toy Chain: a second, minimal chain built purely on `core/` +
//! `circuits/account`, with no dependency on `arxd/*`. It exists to answer
//! one question honestly: which pieces of `arxd` are actually chain-agnostic
//! enough to belong in `core/`? Nothing gets promoted to `core/` until this
//! (or another real chain) needs the exact same code unchanged.
//!
//! It runs a fixed number of blocks against a fresh on-disk DB and prints
//! balances as it goes — no RPC, no networking, no CLI.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use tracing::info;
use xc_executor::execute_actions;
use xc_mempool::Mempool;
use xc_primitives::{Action, AccountEntry, ActionPayload, Address, Block, Snapshot};
use xc_storage::ArxiumDb;

const CHAIN_NAME: &str = "toychain-devnet";
const BLOCKS_TO_PRODUCE: u64 = 3;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_transfer(key: &SigningKey, sender: &Address, nonce: u64, to: &Address, amount: u128) -> Action {
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

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Fresh DB every run — this is a demo, not a persistent devnet.
    let dir = std::env::temp_dir().join("toychain-data");
    std::fs::remove_dir_all(&dir).ok();
    let db = ArxiumDb::open(&dir)?;

    let alice_key = SigningKey::from_bytes(&[11u8; 32]);
    let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes())?;
    let bob = Address::from_pubkey_bytes(&[22u8; 32])?;

    let mut accounts = BTreeMap::new();
    accounts.insert(
        alice.clone(),
        AccountEntry {
            balance: 1_000,
            nonce: 0,
            identity_hash: None,
        },
    );
    accounts.insert(
        bob.clone(),
        AccountEntry {
            balance: 0,
            nonce: 0,
            identity_hash: None,
        },
    );

    let genesis = Block::genesis(now());
    let snapshot = Snapshot {
        height: 0,
        chain_name: CHAIN_NAME.into(),
        accounts,
        validators: BTreeMap::new(),
    };
    db.write_batches(&[&snapshot, &genesis])?;
    info!("genesis written: chain={CHAIN_NAME}");

    let mut mempool = Mempool::new();
    for i in 0..BLOCKS_TO_PRODUCE {
        mempool.push(sign_transfer(&alice_key, &alice, i, &bob, 100))?;
    }

    for _ in 0..BLOCKS_TO_PRODUCE {
        let tip_height = db.get_tip_height()?.unwrap_or(0);
        let parent = db.get_block(tip_height)?.expect("tip block must exist");

        let pending = mempool.drain_pending(1);
        let (applied, updates) = execute_actions(&db, pending)?;

        let block = Block {
            height: tip_height + 1,
            parent_hash: parent.hash(),
            timestamp: now(),
            actions: applied,
            proposer: None,
            signature: None,
        };
        db.write_batches(&[&updates as &dyn xc_storage::BatchWritable, &block])?;

        info!(
            "block {}: alice={} bob={}",
            block.height,
            db.get_account(&alice)?.unwrap().balance,
            db.get_account(&bob)?.unwrap().balance,
        );
    }

    let alice_final = db.get_account(&alice)?.unwrap();
    let bob_final = db.get_account(&bob)?.unwrap();
    println!(
        "final: alice balance={} nonce={}, bob balance={} nonce={}",
        alice_final.balance, alice_final.nonce, bob_final.balance, bob_final.nonce
    );
    assert_eq!(alice_final.balance + bob_final.balance, 1_000);

    Ok(())
}
