mod bootstrap;
mod pair;
pub mod payload;
mod produce;
mod validator;

use crate::bootstrap::bootstrap;
use crate::payload::{ActionPayload, ChainBlock, admission_precheck, dispatch};
use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::Signer;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use finality::{FinalityEvent, PrecommitVote, spawn_finality};
use network::{identity, spawn_p2p_node};
use runtime::{EquivocationEvidence, RuntimeEvent, spawn_runtime};
use xc_cli::{Cli, Command};
use xc_executor::accept_block;
use xc_mempool::Mempool;
use xc_primitives::{Action, Address};
use xc_rpc::spawn_http_ingest;

// ponytail: fixed cadence; make configurable via NodeConfig/CLI if validators need to tune it
const BLOCK_INTERVAL: Duration = Duration::from_secs(2);

// A validator's primary slot lasts this long before the next validator in
// rotation becomes eligible to stand in — double BLOCK_INTERVAL so one
// missed tick from ordinary network jitter doesn't trigger a takeover.
const SLOT_DURATION: Duration = Duration::from_secs(BLOCK_INTERVAL.as_secs() * 2);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Command::NodeKey { base_path }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let keypair = identity::load_or_generate_keypair(base_path)?;
        println!("{}", network::PeerId::from(keypair.public()));
        return Ok(());
    }

    if let Some(Command::BlsKey { base_path, qr }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let (_secret, pubkey) = validator::load_or_generate_bls_key(base_path)?;
        let hex_pubkey = hex::encode(pubkey.0);
        println!("{hex_pubkey}");
        if *qr {
            let code = qrcode::QrCode::new(&hex_pubkey).context("failed to render BLS pubkey as a QR code")?;
            let image = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("{image}");
        }
        return Ok(());
    }

    if let Some(Command::Pair { base_path, node, token, revoke }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        return pair::run(base_path, node, token.as_deref(), *revoke);
    }

    let config = cli.run.into_config();
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

    // Same address as the Ed25519 identity above — a validator's BLS key is
    // only meaningful once its pubkey is registered on-chain via a
    // `RegisterBlsKey` action (`arxd/node/src/payload.rs`), which is an
    // operator step, not automated here.
    let bls_identity = identity
        .as_ref()
        .map(|(address, _)| -> Result<(Address, xc_bls::BlsSecretKey)> {
            let (bls_key, _pubkey) = validator::load_or_generate_bls_key(&config.base_path)?;
            Ok((address.clone(), bls_key))
        })
        .transpose()?;

    // Installs the global recorder the `counter!`/`gauge!` calls below write
    // to; the handle is just a read side onto the same data, handed to the
    // RPC server so `GET /metrics` can render it.
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .context("failed to install metrics recorder")?;
    gauge!("arxium_tip_height").set(db.get_tip_height()?.unwrap_or(0) as f64);

    let mempool = Arc::new(Mutex::new(Mempool::new()));

    // The runtime subsystem's own message-passing seam: `on_block` below
    // sends it competing-block sightings, it decides whether that's real
    // equivocation and (if this node has a validator key) reports it —
    // this thread never calls into slashing logic directly.
    let (runtime_tx, runtime_rx) = std_mpsc::channel();
    let build_evidence_action = identity.as_ref().map(|(address, key)| {
        let address = address.clone();
        let key = key.clone();
        let db = db.clone();
        move |evidence: EquivocationEvidence<ActionPayload>| -> Action<ActionPayload> {
            let nonce = db
                .get_account(&address)
                .ok()
                .flatten()
                .map(|entry| entry.nonce)
                .unwrap_or(0);
            let mut action = Action {
                sender: address.clone(),
                nonce,
                signature: None,
                payload: ActionPayload::SubmitEquivocationEvidence {
                    block_a: Box::new(evidence.block_a),
                    block_b: Box::new(evidence.block_b),
                },
            };
            let signature = key.sign(&action.signing_bytes());
            action.signature = Some(hex::encode(signature.to_bytes()));
            action
        }
    });
    spawn_runtime(
        db.clone(),
        mempool.clone(),
        runtime_rx,
        build_evidence_action,
    );

    // Finality subsystem's own message-passing seam: locally observed
    // blocks and peer precommit votes both funnel in as `FinalityEvent`s;
    // freshly-signed votes come back out on `finality_vote_rx` to be
    // gossiped over the network layer's precommit topic.
    let (finality_event_tx, finality_event_rx) =
        std_mpsc::channel::<FinalityEvent<ActionPayload>>();
    let (finality_vote_tx, finality_vote_rx) = std_mpsc::channel::<PrecommitVote>();
    spawn_finality(
        db.clone(),
        bls_identity,
        finality_event_rx,
        finality_vote_tx,
    );

    let (precommit_tx, precommit_rx) = tokio::sync::mpsc::unbounded_channel::<PrecommitVote>();
    // Bridges `spawn_finality`'s blocking std::sync::mpsc output onto the
    // network layer's tokio channel — same shape as `runtime`/`gossip_tx`
    // bridging elsewhere in this file.
    thread::spawn(move || {
        for vote in finality_vote_rx {
            if precommit_tx.send(vote).is_err() {
                break;
            }
        }
    });

    let on_precommit_vote = {
        let finality_event_tx = finality_event_tx.clone();
        move |vote: PrecommitVote| {
            let _ = finality_event_tx.send(FinalityEvent::VoteObserved(vote));
        }
    };

    // Shared between RPC submission and gossip receipt so a `JoinValidator`/
    // `LeaveValidator`/`RegisterBlsKey` that will actually be rejected by
    // `dispatch` gets rejected here instead, immediately and with a real
    // reason — see `payload::admission_precheck`'s doc comment.
    let payload_precheck: xc_mempool::PayloadPrecheck<ActionPayload> =
        Arc::new(admission_precheck);

    let (gossip_tx, gossip_rx) = tokio::sync::mpsc::unbounded_channel();
    spawn_http_ingest(
        mempool.clone(),
        db.clone(),
        config.rpc_bind.clone(),
        config.port,
        config.rpc_token.clone(),
        Some(gossip_tx),
        metrics_handle,
        Some(payload_precheck.clone()),
        Some(payload::MIN_VALIDATOR_STAKE),
    )?;

    // Guards the read-tip / decide / write critical section shared by this
    // node's own production loop below and the gossip block-accept path, so
    // a self-produced block and a peer's gossiped block for the same height
    // can never both land — whichever gets the lock first wins, and the
    // other observes the advanced tip and backs off.
    let chain_lock = Arc::new(Mutex::new(()));
    let (block_tx, block_rx) = tokio::sync::mpsc::unbounded_channel();

    // Returns `true` only when the block's signature itself didn't verify —
    // unambiguously forged, never just an honest peer relaying something
    // out of order (wrong turn, stale height, etc.) — so the network layer
    // can penalize the sending peer for exactly that case and no other.
    let on_block = {
        let db = db.clone();
        let chain_lock = chain_lock.clone();
        let runtime_tx = runtime_tx.clone();
        let finality_event_tx = finality_event_tx.clone();
        let mempool = mempool.clone();
        move |block: ChainBlock| -> bool {
            let _guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());
            let height = block.height;
            let candidate = block.clone();
            match accept_block(
                &db,
                block,
                SLOT_DURATION.as_secs(),
                |action, lookup, stake_lookup, validator_masters_lookup, operator_lookup, operator_validators_lookup, validators| {
                    dispatch(
                        action,
                        lookup,
                        stake_lookup,
                        validator_masters_lookup,
                        operator_lookup,
                        operator_validators_lookup,
                        validators,
                        height,
                        &|h, p| db.evidence_processed(h, p),
                    )
                },
            ) {
                Ok(accepted) => {
                    info!(
                        "accepted gossiped block {} with {} action(s), hash={}",
                        accepted.height,
                        accepted.actions.len(),
                        accepted.hash()
                    );
                    counter!("arxium_blocks_accepted_total").increment(1);
                    gauge!("arxium_tip_height").set(accepted.height as f64);
                    {
                        let mut mempool = mempool.lock().unwrap_or_else(|e| e.into_inner());
                        for action in &accepted.actions {
                            mempool.purge_stale(&action.sender, action.nonce + 1);
                        }
                    }
                    let _ = finality_event_tx.send(FinalityEvent::BlockObserved(accepted));
                    false
                }
                Err(err) => {
                    warn!("rejected gossiped block: {err}");
                    counter!("arxium_blocks_rejected_total").increment(1);
                    // Competing block for the height we already committed —
                    // not just "behind" — is the one shape that's worth
                    // handing to the runtime subsystem to check for
                    // equivocation.
                    if let xc_executor::AcceptBlockError::NotNextHeight {
                        block_height,
                        tip_height,
                    } = &err
                    {
                        if block_height == tip_height {
                            let _ = runtime_tx.send(RuntimeEvent::BlockObserved(candidate));
                        }
                    }
                    matches!(err, xc_executor::AcceptBlockError::Signature(_))
                }
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
        precommit_rx,
        on_block,
        on_precommit_vote,
        Some(payload_precheck.clone()),
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

    produce::produce_loop(
        &db,
        &mempool,
        identity,
        &chain_lock,
        &finality_event_tx,
        &block_tx,
        &shutdown,
    )
}
