pub mod payload;
mod produce;
mod validator;

use crate::payload::{ActionPayload, ChainBlock, dispatch};
use crate::produce::produce_block;
use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use xc_cli::Cli;
use xc_executor::{accept_block, execute_actions};
use xc_mempool::Mempool;
use xc_network::spawn_p2p_node;
use xc_primitives::{Address, NodeConfig, Snapshot, expected_proposer};
use xc_rpc::spawn_http_ingest;
use xc_storage::ArxiumDb;

const DEVNET_GENESIS_JSON: &str = include_str!("../specs/devnet.json");

// ponytail: fixed cadence; make configurable via NodeConfig/CLI if validators need to tune it
const BLOCK_INTERVAL: Duration = Duration::from_secs(2);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Opens storage and, on a fresh chain, writes the genesis snapshot and block 0.
/// Returns the snapshot too, since the produce loop needs the validator set
/// for round-robin scheduling.
fn bootstrap(config: &NodeConfig) -> Result<(ArxiumDb, Snapshot)> {
    let snapshot = xc_genesis::load_or_init_snapshot(&config.base_path, DEVNET_GENESIS_JSON)?;
    let db = ArxiumDb::open(&config.base_path.join("data"))?;

    if !db.is_initialized()? {
        info!(
            "writing genesis snapshot: chain={} validators={} accounts={}",
            snapshot.chain_name,
            snapshot.validators.len(),
            snapshot.accounts.len()
        );
        db.write_batch(&snapshot)?;
    }

    if db.get_block::<ActionPayload>(0)?.is_none() {
        // Fixed timestamp, not `now_secs()` — every node bootstraps its own
        // copy of genesis independently, and gossiped blocks get checked
        // against local tip's hash, so genesis must hash identically
        // everywhere or block 1 from any peer fails the parent-hash check
        // before it's even out of the gate.
        let genesis_block: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _) =
            execute_actions(&db, genesis_block.actions.clone(), &[], dispatch)?;
        db.write_batches(&[&genesis_updates, &genesis_block])?;
        info!("wrote genesis block: {:?}", genesis_block);
    }

    // Detect on-disk corruption/tampering before building on top of the tip:
    // a signed block whose signature no longer verifies means something is
    // wrong with this node's storage, not with the chain going forward.
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    if let Some(tip_block) = db.get_block::<ActionPayload>(tip_height)?
        && tip_block.signature.is_some()
    {
        tip_block
            .verify_proposer_signature()
            .context("tip block signature failed verification — on-disk corruption or tampering")?;
    }

    Ok((db, snapshot))
}

pub fn run() -> Result<()> {
    let config = Cli::parse().into_config();
    info!("{:?}", config);

    let (db, snapshot) = bootstrap(&config)?;

    // Some((address, key)) if this node produces signed blocks on its turn;
    // None keeps the old always-produce/unsigned solo-node behavior.
    let identity = if config.is_validator {
        let key = validator::load_or_generate_key(&config.base_path)?;
        let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes())?;
        Some((address, key))
    } else {
        None
    };

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let (gossip_tx, gossip_rx) = tokio::sync::mpsc::unbounded_channel();
    spawn_http_ingest(
        mempool.clone(),
        db.clone(),
        config.rpc_bind.clone(),
        config.port,
        config.rpc_token.clone(),
        Some(gossip_tx),
    )?;

    // Guards the read-tip / decide / write critical section shared by this
    // node's own production loop below and the gossip block-accept path, so
    // a self-produced block and a peer's gossiped block for the same height
    // can never both land — whichever gets the lock first wins, and the
    // other observes the advanced tip and backs off.
    let chain_lock = Arc::new(Mutex::new(()));
    let (block_tx, block_rx) = tokio::sync::mpsc::unbounded_channel();

    let on_block = {
        let db = db.clone();
        let chain_lock = chain_lock.clone();
        move |block: ChainBlock| {
            let _guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());
            match accept_block(&db, block, dispatch) {
                Ok(accepted) => info!(
                    "accepted gossiped block {} with {} action(s), hash={}",
                    accepted.height,
                    accepted.actions.len(),
                    accepted.hash()
                ),
                Err(err) => warn!("rejected gossiped block: {err}"),
            }
        }
    };

    // An explicit --bootnodes always wins; otherwise fall back to the chain
    // spec's own boot_nodes list (devnet.json), same role as a Polkadot
    // chain-spec's bootNodes — so a fresh node needs zero flags to join.
    let bootnodes = if config.bootnodes.is_empty() {
        &snapshot.boot_nodes
    } else {
        &config.bootnodes
    };

    // Every node joins the network, not just validators — the libp2p
    // identity is separate from the validator signing key above.
    spawn_p2p_node(
        &config.base_path,
        config.p2p_port,
        bootnodes,
        config.is_bootnode,
        mempool.clone(),
        db.clone(),
        gossip_rx,
        block_rx,
        on_block,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        thread::spawn(move || {
            // ponytail: dedicated runtime just to await ctrl_c; the block-production
            // loop stays plain sync.
            if let Ok(runtime) = tokio::runtime::Runtime::new() {
                runtime.block_on(async {
                    let _ = tokio::signal::ctrl_c().await;
                });
                info!("shutdown signal received, exiting after current block");
                shutdown.store(true, Ordering::Relaxed);
            }
        });
    }

    loop {
        thread::sleep(BLOCK_INTERVAL);

        if shutdown.load(Ordering::Relaxed) {
            info!("shutting down");
            return Ok(());
        }

        // Held for the whole read-tip / decide / write cycle, so a block
        // accepted from gossip in between can't make this node produce a
        // second, conflicting block for the height it just filled — the
        // recomputed `next_height` below will already have moved past it.
        let guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());

        let proposer = match &identity {
            Some((address, key)) => {
                let next_height = db.get_tip_height()?.unwrap_or(0) + 1;
                match expected_proposer(&db.get_validator_set_at(next_height)?, next_height) {
                    Some(expected) if &expected == address => Some((address, key)),
                    Some(_) => {
                        info!("height {next_height}: not our turn, skipping");
                        drop(guard);
                        continue;
                    }
                    None => {
                        warn!("no validators in genesis set, skipping block production");
                        drop(guard);
                        continue;
                    }
                }
            }
            None => None,
        };

        let pending = mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_pending(100);
        // Empty blocks still get produced — height must keep advancing on
        // schedule so `expected_proposer` round-robin doesn't stall waiting
        // for someone to submit an action.
        // A bad action (forged signature, stale nonce) is skipped by execute_actions
        // and never reaches here; an Err means block-level bookkeeping itself failed
        // (e.g. storage), which is unexpected and logged rather than propagated.
        match produce_block(&db, pending, now_secs(), proposer) {
            Ok(block) => {
                info!(
                    "produced block {} with {} action(s), hash={}",
                    block.height,
                    block.actions.len(),
                    block.hash()
                );
                // Only signed blocks are meaningful to peers — an unsigned
                // block (non-validator solo mode) has no proposer for
                // `accept_block`'s expected-proposer check to match.
                if block.signature.is_some() {
                    let _ = block_tx.send(block);
                }
            }
            Err(err) => warn!("block production failed: {err}"),
        }
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_config() -> NodeConfig {
        let base_path = std::env::temp_dir().join(format!(
            "arxium-test-bootstrap-{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        NodeConfig {
            base_path,
            port: 0,
            p2p_port: 0,
            bootnodes: Vec::new(),
            is_bootnode: false,
            is_validator: false,
            rpc_token: None,
            rpc_bind: "127.0.0.1".to_string(),
        }
    }

    #[test]
    fn bootstrap_rejects_tampered_tip_block() {
        let config = test_config();

        // First boot: writes genesis (unsigned, so nothing to verify yet).
        let (db, _snapshot) = bootstrap(&config).unwrap();

        // Produce and sign block 1, same as a real validator would.
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        produce_block(&db, Vec::new(), 1, Some((&address, &key))).unwrap();
        drop(db);

        // Re-opening with an untampered signed tip must succeed.
        bootstrap(&config).unwrap();

        // Tamper with the tip block's content in place, signature unchanged —
        // this must now be caught rather than silently built on top of.
        let db = ArxiumDb::open(&config.base_path.join("data")).unwrap();
        let mut tampered: ChainBlock = db.get_block(1).unwrap().unwrap();
        tampered.timestamp += 1;
        db.write_batch(&tampered).unwrap();
        drop(db);

        assert!(
            bootstrap(&config).is_err(),
            "bootstrap must reject a tip block whose signature no longer verifies"
        );

        std::fs::remove_dir_all(&config.base_path).ok();
    }
}
