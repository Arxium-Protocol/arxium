mod cli;
mod genesis;
mod produce;
mod rpc;
mod validator;

use crate::produce::produce_block;
use crate::rpc::spawn_http_ingest;
use anyhow::Result;
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::cli::Cli;
use xc_executor::execute_actions;
use xc_mempool::Mempool;
use xc_primitives::{Address, Block, NodeConfig, Snapshot, expected_proposer};
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

    if db.get_block(0)?.is_none() {
        let genesis_block = Block::genesis(now_secs());
        execute_actions(&db, genesis_block.actions.clone())?;
        db.write_batch(&genesis_block)?;
        info!("wrote genesis block: {:?}", genesis_block);
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
    // ponytail: no auth/rate-limiting on this endpoint — fine for a devnet operator
    // hitting it directly, add before this is reachable from anywhere untrusted.
    spawn_http_ingest(
        mempool.clone(),
        db.clone(),
        config.rpc_bind.clone(),
        config.port,
        config.rpc_token.clone(),
    )?;

    // ponytail: no graceful shutdown (ctrl-c) yet — add when this stops being a devnet loop.
    loop {
        thread::sleep(BLOCK_INTERVAL);

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
