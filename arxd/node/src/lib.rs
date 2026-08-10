mod cli;
mod genesis;
pub mod payload;
mod produce;
mod rpc;
mod validator;

use crate::payload::{ChainBlock, dispatch};
use crate::produce::produce_block;
use crate::rpc::spawn_http_ingest;
use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::cli::Cli;
use xc_executor::execute_actions;
use xc_mempool::Mempool;
use xc_primitives::{Address, NodeConfig, Snapshot, expected_proposer};
use xc_storage::ArxiumDb;

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
    let snapshot = genesis::load_or_init_snapshot(&config.base_path)?;
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

    if db.get_block::<payload::ActionPayload>(0)?.is_none() {
        let genesis_block: ChainBlock = xc_primitives::Block::genesis(now_secs());
        let (_, genesis_updates) = execute_actions(&db, genesis_block.actions.clone(), dispatch)?;
        db.write_batches(&[&genesis_updates, &genesis_block])?;
        info!("wrote genesis block: {:?}", genesis_block);
    }

    // Detect on-disk corruption/tampering before building on top of the tip:
    // a signed block whose signature no longer verifies means something is
    // wrong with this node's storage, not with the chain going forward.
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    if let Some(tip_block) = db.get_block::<payload::ActionPayload>(tip_height)?
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
    // ponytail: validator set comes from the static genesis snapshot — no
    // join/leave mechanism exists yet, and there's no networking to gossip
    // membership changes even if there were.
    let validator_addrs: Vec<Address> = snapshot.validators.keys().cloned().collect();

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
    spawn_http_ingest(
        mempool.clone(),
        db.clone(),
        config.rpc_bind.clone(),
        config.port,
        config.rpc_token.clone(),
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

        let proposer = match &identity {
            Some((address, key)) => {
                let next_height = db.get_tip_height()?.unwrap_or(0) + 1;
                match expected_proposer(&validator_addrs, next_height) {
                    Some(expected) if &expected == address => Some((address, key)),
                    Some(_) => {
                        info!("height {next_height}: not our turn, skipping");
                        continue;
                    }
                    None => {
                        warn!("no validators in genesis set, skipping block production");
                        continue;
                    }
                }
            }
            None => None,
        };

        let pending = mempool.lock().unwrap().drain_pending(100);
        // Empty blocks still get produced — height must keep advancing on
        // schedule so `expected_proposer` round-robin doesn't stall waiting
        // for someone to submit an action.
        // A bad action (forged signature, stale nonce) is skipped by execute_actions
        // and never reaches here; an Err means block-level bookkeeping itself failed
        // (e.g. storage), which is unexpected and logged rather than propagated.
        match produce_block(&db, pending, now_secs(), proposer) {
            Ok(block) => info!(
                "produced block {} with {} action(s), hash={}",
                block.height,
                block.actions.len(),
                block.hash()
            ),
            Err(err) => warn!("block production failed: {err}"),
        }
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
