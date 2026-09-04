// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

mod components;
mod produce;
mod validator;

use crate::components::new_partial;
use xc_runtime_api::ChainRuntime;
use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::Signer;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use xc_evidence::{EquivocationEvidence, EvidenceEvent, spawn_evidence_watcher};
use arxd_finality::{
    Dissent, DissentReason, FinalityEvent, PrecommitVote, RoundTimeoutVote, dissent_signing_bytes, spawn_finality,
};
use arxd_network::{identity, spawn_p2p_node};
use xc_artifact::DissentAttestation;
use xc_cli::{Cli, Command};
use xc_executor::{AcceptBlockError, accept_block};
use xc_mempool::Mempool;
use xc_primitives::{Action, Address, Block};
use xc_rpc::spawn_http_ingest;
use xc_storage::{ArxiumDb, DissentRecord};

// ponytail: fixed cadence; make configurable via NodeConfig/CLI if validators need to tune it
const BLOCK_INTERVAL: Duration = Duration::from_secs(2);

// A validator's primary slot lasts this long before the next validator in
// rotation becomes eligible to stand in — double BLOCK_INTERVAL so one
// missed tick from ordinary network jitter doesn't trigger a takeover.
const SLOT_DURATION: Duration = Duration::from_secs(BLOCK_INTERVAL.as_secs() * 2);

/// A block strictly behind our tip (`block_height < tip_height`) is an
/// ordinary, expected race — already applied via the other delivery path
/// (gossip vs. sync) while this one was in flight — not evidence of
/// anything wrong. Logging it at `warn!` for every block in a sync page was
/// a major contributor to a 40GB-of-syslog incident: keep everything else
/// (ahead of tip, parent mismatch, bad signature, equivocation-shaped
/// `block_height == tip_height`) at `warn!`, since those are the shapes
/// worth an operator's attention.
fn is_routine_reject(err: &xc_executor::AcceptBlockError) -> bool {
    matches!(
        err,
        xc_executor::AcceptBlockError::NotNextHeight { block_height, tip_height }
            if block_height < tip_height
    )
}

#[cfg(test)]
mod reject_severity_tests {
    use super::is_routine_reject;
    use xc_executor::AcceptBlockError;

    #[test]
    fn behind_tip_is_routine() {
        let err = AcceptBlockError::NotNextHeight {
            block_height: 10,
            tip_height: 20,
        };
        assert!(is_routine_reject(&err));
    }

    #[test]
    fn equal_to_tip_is_not_routine() {
        // Competing block at an already-committed height — equivocation-shaped.
        let err = AcceptBlockError::NotNextHeight {
            block_height: 20,
            tip_height: 20,
        };
        assert!(!is_routine_reject(&err));
    }

    #[test]
    fn ahead_of_tip_is_not_routine() {
        let err = AcceptBlockError::NotNextHeight {
            block_height: 30,
            tip_height: 20,
        };
        assert!(!is_routine_reject(&err));
    }

    #[test]
    fn parent_mismatch_is_not_routine() {
        let err = AcceptBlockError::ParentMismatch {
            local: "a".into(),
            expected: "b".into(),
        };
        assert!(!is_routine_reject(&err));
    }
}

/// `arxd-node` is the only crate that already depends on both `arxd-finality`
/// and `xc-artifact`, so it's the natural home for a direct cross-crate
/// equality check on top of the frozen-vector test each of those two crates
/// carries individually (`frozen_dissent_signing_bytes_vector`). Neither
/// frozen vector alone can catch the two copies drifting apart — each only
/// proves its own crate is internally self-consistent — so this is the test
/// that actually enforces the invariant the doc comments on both functions
/// claim.
#[cfg(test)]
mod dissent_cross_crate_tests {
    #[test]
    fn dissent_signing_bytes_match_across_crates() {
        let header_commitment = [4u8; 32];
        let ep = [7u8; 32];
        assert_eq!(
            arxd_finality::dissent_signing_bytes(
                5,
                "0xblock",
                "0xstate",
                &header_commitment,
                &ep,
                "state_root_mismatch"
            ),
            xc_artifact::dissent_signing_bytes(
                5,
                "0xblock",
                "0xstate",
                &header_commitment,
                &ep,
                "state_root_mismatch"
            ),
        );
    }
}

/// Covers `dissent_record_to_evidence_event` — the piece that closes Part 2's
/// gap: a peer's dissent, once persisted by `arxd/finality`, must produce the
/// same evidence artifact a local rejection would, provided this node holds
/// the disputed block.
#[cfg(test)]
mod dissent_evidence_bridge_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signed_block(key: &SigningKey, height: u64, timestamp: u64) -> Block<()> {
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(timestamp);
        block.height = height;
        block.sign(addr, key);
        block
    }

    fn open_test_db() -> (ArxiumDb, std::path::PathBuf) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-node-dissent-evidence-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        (ArxiumDb::open(&dir).expect("open test db"), dir)
    }

    fn sample_record(height: u64, block_hash: String, voter: Address) -> DissentRecord {
        DissentRecord {
            height,
            block_hash,
            state_root: "0xdisputed".to_string(),
            header_commitment: [4u8; 32],
            ep: [9u8; 32],
            reason: "state_root_mismatch".to_string(),
            voter,
            signature: xc_bls::BlsSignature([3u8; 96]),
        }
    }

    #[test]
    fn builds_the_same_artifact_a_local_rejection_would_for_a_block_this_node_holds() {
        let (db, dir) = open_test_db();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let block = signed_block(&key, 5, 100);
        db.write_batches(&[&block]).unwrap();

        let voter = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (_sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
        db.write_batches(&[&xc_storage::BlsKeyRegistration {
            address: voter.clone(),
            pubkey: pk,
            effective_height: 0,
        }])
        .unwrap();

        let record = sample_record(5, block.hash(), voter.clone());
        let event = dissent_record_to_evidence_event::<()>(&db, record)
            .expect("a locally-held block with a registered voter key must yield an artifact event");

        match event {
            EvidenceEvent::ExecutionDisagreement { proposed, dissent } => {
                assert_eq!(proposed.hash(), block.hash());
                assert_eq!(dissent.height, 5);
                assert_eq!(dissent.voter, voter.to_string());
                assert_eq!(dissent.reason, "state_root_mismatch");
            }
            EvidenceEvent::BlockObserved(_) => panic!("expected ExecutionDisagreement"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_without_panicking_when_the_disputed_block_is_not_held_locally() {
        let (db, dir) = open_test_db();
        let voter = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let record = sample_record(5, "0xnotheld".to_string(), voter);

        assert!(
            dissent_record_to_evidence_event::<()>(&db, record).is_none(),
            "a block this node never received must not synthesize an artifact"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// How often the "not producing" line may repeat. A skip happens every
/// couple of seconds on a node that isn't the current proposer, so logging
/// each one would bury everything else; the counter carries the exact
/// count, the log only has to make the situation visible.
pub(crate) const SKIP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Silence beyond which a skip stops being routine. A full rotation takes
/// `validators * SLOT_DURATION`, so several rotations with nobody producing
/// means it isn't simply someone else's turn — that is the stall shape, and
/// it escalates the log line from info to warn.
pub(crate) const STALL_SUSPECT_AFTER: Duration = Duration::from_secs(SLOT_DURATION.as_secs() * 10);

/// Both tip gauges, always set together — three separate sites advance the
/// tip (startup, a produced block, an accepted block) and they must not
/// drift apart.
///
/// `arxium_tip_timestamp_seconds` is the one that actually detects a stall.
/// `arxium_tip_height` holds a constant value on a stalled chain and on a
/// merely quiet one alike, so monitoring cannot tell them apart without
/// diffing it over time; exporting the tip's own timestamp turns that into
/// a single expression, `now - arxium_tip_timestamp_seconds > N`. The
/// original stall ran ~17 hours unnoticed for exactly this reason.
pub(crate) fn record_tip(height: u64, timestamp: u64) {
    gauge!("arxium_tip_height").set(height as f64);
    gauge!("arxium_tip_timestamp_seconds").set(timestamp as f64);
}

/// Wraps a spawned subsystem thread so a panic inside it is fatal to the
/// whole node instead of silently vanishing — previously a panicking
/// evidence/finality/bridge thread just stopped and the node kept running
/// with that subsystem dead, with nothing in the logs to say why block
/// production or finalization had quietly stalled.
///
/// A plain (non-panicking) return is logged and counted but not fatal: the
/// ctrl-c watcher and the precommit bridge both return normally as part of
/// an ordinary shutdown, once the channels they depend on start closing.
fn spawn_supervised(name: &'static str, handle: thread::JoinHandle<()>) {
    thread::spawn(move || match handle.join() {
        Ok(()) => {
            debug!("subsystem '{name}' thread exited");
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            error!("subsystem '{name}' thread panicked: {msg}");
            counter!("arxium_subsystem_exit_total", "subsystem" => name).increment(1);
            std::process::exit(1);
        }
    });
}

/// Everything `spawn_subsystems` builds that `run()` still needs afterward:
/// the closures/receivers `spawn_p2p_node` consumes, and the shared state
/// `produce::produce_loop` reads.
struct SubsystemHandles<R: ChainRuntime> {
    bootnodes: Vec<String>,
    chain_lock: Arc<Mutex<()>>,
    finality_event_tx: std_mpsc::Sender<FinalityEvent<R::Payload>>,
    block_tx: tokio::sync::mpsc::UnboundedSender<Block<R::Payload>>,
    block_rx: tokio::sync::mpsc::UnboundedReceiver<Block<R::Payload>>,
    gossip_rx: tokio::sync::mpsc::UnboundedReceiver<Action<R::Payload>>,
    precommit_rx: tokio::sync::mpsc::UnboundedReceiver<PrecommitVote>,
    dissent_rx: tokio::sync::mpsc::UnboundedReceiver<Dissent>,
    round_timeout_rx: tokio::sync::mpsc::UnboundedReceiver<RoundTimeoutVote>,
    on_block: Box<dyn Fn(Block<R::Payload>, bool) -> bool + Send>,
    on_precommit_vote: Box<dyn Fn(PrecommitVote) + Send>,
    on_dissent: Box<dyn Fn(Dissent) + Send>,
    on_round_timeout_vote: Box<dyn Fn(RoundTimeoutVote) + Send>,
    payload_precheck: xc_mempool::PayloadPrecheck<R::Payload>,
    shutdown: Arc<AtomicBool>,
}

/// Turns a `DissentRecord` `arxd/finality` just persisted (whether signed
/// locally or received over gossip) into the `ExecutionDisagreement`
/// evidence event, by reading back the disputed block and the dissenter's
/// registered BLS key from local storage. Returns `None` (and lets the
/// caller decide whether to warn) when either read comes up empty — a node
/// that never received the disputed block has nothing to build a
/// `BlockAttestation` from, and synthesizing one from fields it didn't
/// actually read would turn the artifact into an unverified guess.
fn dissent_record_to_evidence_event<P: serde::de::DeserializeOwned>(
    db: &ArxiumDb,
    record: DissentRecord,
) -> Option<EvidenceEvent<P>> {
    let proposed: Block<P> = match db.get_block(record.height) {
        Ok(Some(block)) => block,
        Ok(None) => {
            warn!(
                "dissent at height {} for a block not held locally, skipping evidence artifact",
                record.height
            );
            return None;
        }
        Err(err) => {
            warn!("failed to read block at height {} for dissent evidence: {err}", record.height);
            return None;
        }
    };
    let voter_pubkey = match db.get_bls_pubkey_at(&record.voter, record.height) {
        Ok(Some(pubkey)) => pubkey,
        Ok(None) => {
            warn!(
                "no registered BLS key for dissenter {} at height {}, skipping evidence artifact",
                record.voter, record.height
            );
            return None;
        }
        Err(err) => {
            warn!("failed to read BLS key for dissenter {}: {err}", record.voter);
            return None;
        }
    };
    let attestation = DissentAttestation {
        height: record.height,
        block_hash: record.block_hash,
        state_root: record.state_root,
        header_commitment: format!("0x{}", hex::encode(record.header_commitment)),
        ep: format!("0x{}", hex::encode(record.ep)),
        reason: record.reason,
        voter: record.voter.to_string(),
        voter_pubkey: format!("0x{}", hex::encode(voter_pubkey.0)),
        signature: format!("0x{}", hex::encode(record.signature.0)),
    };
    Some(EvidenceEvent::ExecutionDisagreement { proposed, dissent: attestation })
}

/// Spawns every subsystem thread (evidence watcher, finality, the
/// precommit-vote bridge, RPC ingest, the ctrl-c watcher) and wires the
/// channels/closures between them. Everything `spawn_p2p_node` and
/// `produce::produce_loop` need afterward comes back in `SubsystemHandles`;
/// network spawning and the produce loop itself stay in `run()` since they
/// aren't "subsystems" spawned here so much as `run()`'s own next steps.
fn spawn_subsystems<R: ChainRuntime>(
    config: &xc_primitives::NodeConfig,
    chain_name: &str,
    genesis_hash: [u8; 32],
    db: &ArxiumDb,
    mempool: &Arc<Mutex<Mempool<R::Payload>>>,
    identity: &Option<(Address, ed25519_dalek::SigningKey)>,
    bls_identity: Option<(Address, xc_bls::BlsSecretKey)>,
    boot_nodes: &[String],
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> Result<SubsystemHandles<R>> {
    // The evidence subsystem's own message-passing seam: `on_block` below
    // sends it competing-block sightings, it decides whether that's real
    // equivocation and (if this node has a validator key) reports it —
    // this thread never calls into slashing logic directly.
    let (evidence_tx, evidence_rx) = std_mpsc::channel();
    // Not every runtime reports equivocation (e.g. a spoke chain with no
    // slashing action); probe once at startup with empty dummy blocks
    // instead of threading an `Option` return through the watcher's
    // per-event hot path.
    let build_evidence_action = identity.as_ref().and_then(|(address, key)| {
        let dummy_block = || Block {
            height: 0,
            parent_hash: String::new(),
            timestamp: 0,
            actions: Vec::new(),
            tx_root: [0u8; 32],
            proposer: None,
            signature: None,
            state_root: String::new(),
            round: 0,
            round_certificate: None,
        };
        R::build_evidence_action(
            EquivocationEvidence { block_a: dummy_block(), block_b: dummy_block() },
            address,
            0,
        )?;

        let address = address.clone();
        let key = key.clone();
        let db = db.clone();
        Some(move |evidence: EquivocationEvidence<R::Payload>| -> Action<R::Payload> {
            let nonce = db
                .get_account(&address)
                .ok()
                .flatten()
                .map(|entry| entry.nonce)
                .unwrap_or(0);
            let mut action = R::build_evidence_action(evidence, &address, nonce)
                .expect("probed Some for this runtime at startup");
            let signature = key.sign(&action.signing_bytes());
            action.signature = Some(hex::encode(signature.to_bytes()));
            action
        })
    });
    spawn_supervised(
        "evidence",
        spawn_evidence_watcher(
            db.clone(),
            mempool.clone(),
            evidence_rx,
            build_evidence_action,
            config.base_path.join(chain_name).join("evidence"),
            genesis_hash,
        ),
    );

    // Finality subsystem's own message-passing seam: locally observed
    // blocks and peer precommit votes both funnel in as `FinalityEvent`s;
    // freshly-signed votes come back out on `finality_vote_rx` to be
    // gossiped over the network layer's precommit topic.
    let (finality_event_tx, finality_event_rx) =
        std_mpsc::channel::<FinalityEvent<R::Payload>>();
    let (finality_vote_tx, finality_vote_rx) = std_mpsc::channel::<PrecommitVote>();
    let (finality_round_timeout_tx, finality_round_timeout_rx) =
        std_mpsc::channel::<RoundTimeoutVote>();
    // Every dissent `spawn_finality` newly persists — whether signed
    // locally or received from a peer — comes back out here so it can be
    // turned into the same evidence artifact either way (see
    // `dissent_evidence_bridge` below). Closes the gap where only the
    // local-rejection path used to produce one.
    let (dissent_recorded_tx, dissent_recorded_rx) = std_mpsc::channel::<DissentRecord>();
    // `on_block` below also needs the BLS key to sign dissents on execution
    // disagreement, so clone before `spawn_finality` consumes the original.
    let bls_identity_for_dissent = bls_identity.clone();
    spawn_supervised(
        "finality",
        spawn_finality(
            db.clone(),
            bls_identity,
            finality_event_rx,
            finality_vote_tx,
            finality_round_timeout_tx,
            dissent_recorded_tx,
        ),
    );

    // Turns a persisted `DissentRecord` into the same `ExecutionDisagreement`
    // evidence artifact the local-rejection path emits below — the only
    // difference is the disputed block is read back from local storage
    // instead of being the block this node just rejected. If this node
    // never received that block, it stays quiet rather than synthesizing a
    // `BlockAttestation` from fields it never actually read (same principle
    // as the parent-lookup fallback further down): the `DissentRecord` is
    // still persisted either way, just without an artifact.
    spawn_supervised("dissent_evidence_bridge", {
        let db = db.clone();
        let evidence_tx = evidence_tx.clone();
        thread::spawn(move || {
            for record in dissent_recorded_rx {
                if let Some(event) = dissent_record_to_evidence_event::<R::Payload>(&db, record) {
                    let _ = evidence_tx.send(event);
                }
            }
        })
    });

    let (precommit_tx, precommit_rx) = tokio::sync::mpsc::unbounded_channel::<PrecommitVote>();
    // Bridges `spawn_finality`'s blocking std::sync::mpsc output onto the
    // network layer's tokio channel — same shape as `evidence`/`gossip_tx`
    // bridging elsewhere in this file.
    spawn_supervised(
        "precommit_bridge",
        thread::spawn(move || {
            for vote in finality_vote_rx {
                if precommit_tx.send(vote).is_err() {
                    break;
                }
            }
        }),
    );

    let (round_timeout_tx, round_timeout_rx) =
        tokio::sync::mpsc::unbounded_channel::<RoundTimeoutVote>();
    // Bridges the round-timeout equivalent of `finality_vote_rx` — same
    // shape as `precommit_bridge` above.
    spawn_supervised(
        "round_timeout_bridge",
        thread::spawn(move || {
            for vote in finality_round_timeout_rx {
                if round_timeout_tx.send(vote).is_err() {
                    break;
                }
            }
        }),
    );

    let on_precommit_vote: Box<dyn Fn(PrecommitVote) + Send> = {
        let finality_event_tx = finality_event_tx.clone();
        Box::new(move |vote: PrecommitVote| {
            let _ = finality_event_tx.send(FinalityEvent::VoteObserved(vote));
        })
    };

    let on_round_timeout_vote: Box<dyn Fn(RoundTimeoutVote) + Send> = {
        let finality_event_tx = finality_event_tx.clone();
        Box::new(move |vote: RoundTimeoutVote| {
            let _ = finality_event_tx.send(FinalityEvent::RoundTimeoutObserved(vote));
        })
    };

    let on_dissent: Box<dyn Fn(Dissent) + Send> = {
        let finality_event_tx = finality_event_tx.clone();
        Box::new(move |dissent: Dissent| {
            let _ = finality_event_tx.send(FinalityEvent::DissentObserved(dissent));
        })
    };

    let (dissent_tx, dissent_rx) = tokio::sync::mpsc::unbounded_channel::<Dissent>();

    // Shared between RPC submission and gossip receipt so a `JoinValidator`/
    // `LeaveValidator`/`RegisterBlsKey` that will actually be rejected by
    // `dispatch` gets rejected here instead, immediately and with a real
    // reason — see `ChainRuntime::admission_precheck`'s doc comment.
    let payload_precheck: xc_mempool::PayloadPrecheck<R::Payload> = Arc::new(R::admission_precheck);

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
        R::min_validator_stake(),
        Some(R::action_fee()),
        config.base_path.join(chain_name).join("evidence"),
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
    let on_block: Box<dyn Fn(Block<R::Payload>, bool) -> bool + Send> = {
        let db = db.clone();
        let chain_lock = chain_lock.clone();
        let evidence_tx = evidence_tx.clone();
        let finality_event_tx = finality_event_tx.clone();
        let mempool = mempool.clone();
        let bls_identity = bls_identity_for_dissent.clone();
        let dissent_tx = dissent_tx.clone();
        Box::new(move |block: Block<R::Payload>, sync: bool| -> bool {
            let _guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());
            let height = block.height;
            let candidate = block.clone();
            match accept_block(
                &db,
                block,
                sync,
                R::action_fee(),
                |action, view, operator_lookup, operator_validators_lookup, validators| {
                    R::dispatch(
                        action,
                        &xc_runtime_api::DispatchCtx {
                            view,
                            db: &db,
                            operator_lookup,
                            operator_validators_lookup,
                            validators,
                            height,
                        },
                    )
                },
                R::on_block_sealed,
            ) {
                Ok(accepted) => {
                    // During sync catch-up this fires once per block in a
                    // page (up to 100) — logging each at info level is what
                    // produced tens of thousands of lines during a large
                    // catch-up. The caller logs one summary per page instead;
                    // live gossip acceptance (naturally bounded by block
                    // production rate) still gets its own info line.
                    if sync {
                        debug!(
                            "accepted synced block {} with {} action(s), hash={}",
                            accepted.height,
                            accepted.actions.len(),
                            accepted.hash()
                        );
                    } else {
                        info!(
                            "accepted gossiped block {} with {} action(s), hash={}",
                            accepted.height,
                            accepted.actions.len(),
                            accepted.hash()
                        );
                    }
                    counter!("arxium_blocks_accepted_total").increment(1);
                    record_tip(accepted.height, accepted.timestamp);
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
                    counter!("arxium_blocks_rejected_total").increment(1);
                    // A block strictly behind our tip is an ordinary,
                    // expected race — already applied via the other delivery
                    // path (gossip vs. sync) while this one was in flight —
                    // not evidence of anything wrong, so it doesn't deserve
                    // warn. Competing block for the height we already
                    // committed (`block_height == tip_height`) is the one
                    // shape worth both a warn and handing to the evidence watcher
                    // subsystem to check for equivocation; anything else
                    // (ahead of tip, parent mismatch, bad signature, etc.)
                    // stays at warn too.
                    if is_routine_reject(&err) {
                        debug!("rejected gossiped block: {err}");
                    } else {
                        warn!("rejected gossiped block: {err}");
                        if err.is_execution_disagreement() {
                            if let Some((address, bls_key)) = &bls_identity {
                                // Only these two variants should reach here — see
                                // `AcceptBlockError::is_execution_disagreement`. That
                                // classifier lives in a different crate than this
                                // match, though, so a future variant added there
                                // without a matching arm here must not panic the
                                // block-handling path: skip the dissent instead.
                                let dissent_fields = match &err {
                                    AcceptBlockError::StateRootMismatch { expected, .. } => {
                                        Some((expected.clone(), DissentReason::StateRootMismatch))
                                    }
                                    AcceptBlockError::ActionMismatch { local_state_root, .. } => {
                                        Some((local_state_root.clone(), DissentReason::ActionMismatch))
                                    }
                                    _ => {
                                        warn!(
                                            "is_execution_disagreement() true for a variant this match doesn't \
                                             handle ({err}) — skipping dissent, not panicking"
                                        );
                                        None
                                    }
                                };
                                if let Some((state_root, reason)) = dissent_fields {
                                // TODO(security): a node that can't read its own
                                // parent falls back to computing its EP from `""`
                                // rather than staying quiet — safe for *agreement*
                                // between honest nodes (every honest node hits the
                                // same fallback, so quorum still forms), but once
                                // dissent carries slashing consequences this is a
                                // signed claim built on data the node never actually
                                // read. Should go quiet here instead, same principle
                                // that excludes `Storage` errors from
                                // `is_execution_disagreement` in the first place.
                                let parent_state_root =
                                    match db.get_block::<R::Payload>(height.saturating_sub(1)) {
                                        Ok(Some(parent)) => parent.state_root,
                                        Ok(None) => String::new(),
                                        Err(err) => {
                                            warn!(
                                                "failed to read parent block {} for dissent EP: {err}",
                                                height.saturating_sub(1)
                                            );
                                            String::new()
                                        }
                                    };
                                let block_hash = candidate.hash();
                                let ep = xc_poe::block_ep(&parent_state_root, &candidate.tx_root, &state_root);
                                let proposer = candidate
                                    .proposer
                                    .as_ref()
                                    .expect("signature already verified, proposer present");
                                let header_commitment: [u8; 32] =
                                    Sha256::digest(candidate.signing_bytes(proposer)).into();
                                let msg = dissent_signing_bytes(
                                    height,
                                    &block_hash,
                                    &state_root,
                                    &header_commitment,
                                    &ep,
                                    reason.as_str(),
                                );
                                let signature = xc_bls::sign(bls_key, &msg);
                                let dissent = Dissent {
                                    height,
                                    block_hash,
                                    state_root,
                                    header_commitment,
                                    ep,
                                    reason,
                                    voter: address.clone(),
                                    signature,
                                };
                                let _ = finality_event_tx.send(FinalityEvent::DissentObserved(dissent.clone()));
                                let _ = dissent_tx.send(dissent.clone());
                                if let Ok(Some(pubkey)) = db.get_bls_pubkey(address) {
                                    let attestation = DissentAttestation {
                                        height: dissent.height,
                                        block_hash: dissent.block_hash.clone(),
                                        state_root: dissent.state_root.clone(),
                                        header_commitment: format!("0x{}", hex::encode(dissent.header_commitment)),
                                        ep: format!("0x{}", hex::encode(dissent.ep)),
                                        reason: reason.as_str().to_string(),
                                        voter: address.to_string(),
                                        voter_pubkey: format!("0x{}", hex::encode(pubkey.0)),
                                        signature: format!("0x{}", hex::encode(dissent.signature.0)),
                                    };
                                    let _ = evidence_tx.send(EvidenceEvent::ExecutionDisagreement {
                                        proposed: candidate.clone(),
                                        dissent: attestation,
                                    });
                                }
                                }
                            }
                        } else if let xc_executor::AcceptBlockError::NotNextHeight {
                            block_height,
                            tip_height,
                        } = &err
                        {
                            if block_height == tip_height {
                                let _ = evidence_tx.send(EvidenceEvent::BlockObserved(candidate));
                            }
                        }
                    }
                    matches!(err, xc_executor::AcceptBlockError::Signature(_))
                }
            }
        })
    };

    // An explicit --bootnodes always wins; otherwise fall back to the chain
    // spec's own boot_nodes list (devnet.json) — so a fresh node needs zero
    // flags to join.
    let bootnodes = if config.bootnodes.is_empty() {
        boot_nodes.to_vec()
    } else {
        config.bootnodes.clone()
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        spawn_supervised(
            "ctrl_c_watcher",
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
            }),
        );
    }

    Ok(SubsystemHandles {
        bootnodes,
        chain_lock,
        finality_event_tx,
        block_tx,
        block_rx,
        gossip_rx,
        precommit_rx,
        dissent_rx,
        round_timeout_rx,
        on_block,
        on_precommit_vote,
        on_dissent,
        on_round_timeout_vote,
        payload_precheck,
        shutdown,
    })
}

pub fn run<R: ChainRuntime>() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Command::NodeKey { base_path }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let keypair = identity::load_or_generate_keypair(base_path)?;
        println!("{}", arxd_network::PeerId::from(keypair.public()));
        return Ok(());
    }

    if let Some(Command::Keys {
        base_path,
        json,
        stake,
    }) = &cli.command
    {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;

        let validator_key = validator::load_or_generate_key(base_path)?;
        let address = Address::from_pubkey_bytes(validator_key.verifying_key().as_bytes())?;
        let (_bls_secret, bls_pubkey) = validator::load_or_generate_bls_key(base_path)?;
        let bls_hex = hex::encode(bls_pubkey.0);
        let peer_id =
            arxd_network::PeerId::from(identity::load_or_generate_keypair(base_path)?.public());

        // Built from `ValidatorEntry` itself rather than hand-written JSON, so
        // the field names cannot drift from what the spec loader expects —
        // a mismatch here would produce output that looks right and silently
        // fails to register a key.
        let entry = std::collections::BTreeMap::from([(
            address.clone(),
            xc_primitives::ValidatorEntry {
                stake: *stake,
                bls_pubkey: Some(bls_hex.clone()),
            },
        )]);
        let entry_json = serde_json::to_string_pretty(&entry)
            .context("failed to render the chain-spec entry")?;

        if *json {
            println!("{entry_json}");
            return Ok(());
        }

        println!();
        println!("  Validator address   {address}");
        println!("  BLS finality key    {bls_hex}");
        println!("  libp2p peer ID      {peer_id}");
        println!();
        println!("  Chain-spec entry — merge into \"validators\" in the genesis spec:");
        println!();
        for line in entry_json.lines() {
            println!("    {line}");
        }
        println!();
        println!("  The validator address must appear in the chain spec's validator set,");
        println!("  or be added later with JoinValidator, or this node never produces a");
        println!("  block. Without the BLS key it can produce but never vote on finality,");
        println!("  while still counting toward the quorum it cannot help meet.");
        println!();
        return Ok(());
    }

    if let Some(Command::ValidatorKey { base_path }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let key = validator::load_or_generate_key(base_path)?;
        println!(
            "{}",
            Address::from_pubkey_bytes(key.verifying_key().as_bytes())?
        );
        return Ok(());
    }

    if let Some(Command::BlsKey { base_path, qr }) = &cli.command {
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let (_secret, pubkey) = validator::load_or_generate_bls_key(base_path)?;
        let hex_pubkey = hex::encode(pubkey.0);
        println!("{hex_pubkey}");
        if *qr {
            let code = qrcode::QrCode::new(&hex_pubkey)
                .context("failed to render BLS pubkey as a QR code")?;
            let image = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("{image}");
        }
        return Ok(());
    }

    if let Some(Command::Pair {
        base_path,
        node,
        token,
        revoke,
    }) = &cli.command
    {
        // The pairing session this command creates lives only in this node
        // process's memory (see core/rpc's PairingStore) — printed up front
        // so a mismatch against whatever node the app's backend actually
        // talks to (NODE_RPC_URL) is obvious immediately, not after a
        // confusing "expired" report from the app minutes later.
        println!("Connecting to node at {node}{}", if token.is_some() { " (with token)" } else { "" });
        std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
        let key = validator::load_or_generate_key(base_path)?;
        let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes())
            .context("validator key produced an invalid address")?;
        return R::pair(&key.to_bytes(), &sender, node, token.as_deref(), *revoke);
    }

    if let Some(Command::Snapshot {
        base_path,
        chain,
        output,
    }) = &cli.command
    {
        // Read-only, so goes through `new_partial` like the running node
        // does rather than opening the DB by hand — same tip-signature
        // verification, same genesis-write-on-first-run behavior, so a
        // snapshot taken from data nothing else has ever booted still works.
        // `is_validator: false` (the default below) means no key material
        // gets generated just to export a checkpoint.
        let config = xc_primitives::NodeConfig {
            base_path: base_path.clone(),
            chain: chain.clone(),
            port: 0,
            p2p_port: 0,
            bootnodes: Vec::new(),
            is_bootnode: false,
            is_validator: false,
            rpc_token: None,
            rpc_bind: "127.0.0.1".to_string(),
        };
        let components = new_partial::<R>(&config)?;
        components.db.export_checkpoint(output).with_context(|| {
            format!(
                "failed to write checkpoint to {} (must not already exist)",
                output.display()
            )
        })?;
        let tip = components.db.get_tip_height()?.unwrap_or(0);
        println!(
            "wrote checkpoint at tip height {tip} to {}",
            output.display()
        );
        return Ok(());
    }

    if let Some(Command::ChainInfo { chain, list }) = &cli.command {
        if *list {
            for name in R::presets().names() {
                println!("{name}");
            }
            return Ok(());
        }
        let spec_json = xc_chain_spec::resolve_chain_spec(chain, R::presets())?;
        let chain_spec = arxd_genesis::ChainSpec::parse(&spec_json)?;
        match &chain_spec {
            arxd_genesis::ChainSpec::Plain(snapshot) => {
                snapshot
                    .validate()
                    .context("chain spec failed validation")?;
                println!("format:         plain");
                println!("chain name:     {}", snapshot.chain_name);
                // ponytail: genesis hash needs the state actually reached at
                // genesis, which means opening a DB — skipped for a plain
                // spec so `chain-info` stays a zero-RocksDB preview; use
                // `arx-spec-builder inspect` for the real hash.
                println!(
                    "genesis hash:   <derive with `arx-spec-builder inspect`, or boot the node>"
                );
                println!("validators:     {}", snapshot.validators.len());
                println!("accounts:       {}", snapshot.accounts.len());
                println!("boot nodes:     {}", snapshot.boot_nodes.len());
            }
            arxd_genesis::ChainSpec::Raw(raw) => {
                println!(
                    "format:         raw (format_version {})",
                    raw.format_version
                );
                println!("chain name:     {}", raw.chain_name);
                println!("genesis hash:   {}", raw.state_root);
                println!("source spec:    {}", raw.source_spec_hash);
                println!("boot nodes:     {}", raw.boot_nodes.len());
                println!("entries:        {}", raw.entries.len());
            }
        }
        return Ok(());
    }

    if let Some(Command::ChainSpec { chain }) = &cli.command {
        let spec_json = xc_chain_spec::resolve_chain_spec(chain, R::presets())?;
        println!("{spec_json}");
        return Ok(());
    }

    let config = cli.run.into_config();
    info!("{:?}", config);

    let components::NodeComponents {
        db,
        chain_name,
        boot_nodes,
        genesis_hash,
        identity,
        bls_identity,
        mempool,
        ..
    } = new_partial::<R>(&config)?;
    let chain_id = hex::encode(genesis_hash);
    info!("booted chain={chain_name} genesis={chain_id}");

    // Installs the global recorder the `counter!`/`gauge!` calls below write
    // to; the handle is just a read side onto the same data, handed to the
    // RPC server so `GET /metrics` can render it.
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .context("failed to install metrics recorder")?;
    // Seeded at startup so a node that comes up already stalled reports a
    // stale tip immediately, rather than exporting nothing until the first
    // block it never produces.
    let startup_tip = db.get_tip_height()?.unwrap_or(0);
    let startup_tip_timestamp = db
        .get_block::<R::Payload>(startup_tip)?
        .map(|b: Block<R::Payload>| b.timestamp)
        .unwrap_or(0);
    record_tip(startup_tip, startup_tip_timestamp);

    let SubsystemHandles {
        bootnodes,
        chain_lock,
        finality_event_tx,
        block_tx,
        block_rx,
        gossip_rx,
        precommit_rx,
        dissent_rx,
        round_timeout_rx,
        on_block,
        on_precommit_vote,
        on_dissent,
        on_round_timeout_vote,
        payload_precheck,
        shutdown,
    } = spawn_subsystems::<R>(
        &config,
        &chain_name,
        genesis_hash,
        &db,
        &mempool,
        &identity,
        bls_identity,
        &boot_nodes,
        metrics_handle,
    )?;

    // Every node joins the network, not just validators — the libp2p
    // identity is separate from the validator signing key above.
    spawn_p2p_node(
        &config.base_path,
        config.p2p_port,
        &bootnodes,
        config.is_bootnode,
        &chain_id,
        mempool.clone(),
        db.clone(),
        gossip_rx,
        block_rx,
        precommit_rx,
        dissent_rx,
        round_timeout_rx,
        on_block,
        on_precommit_vote,
        on_dissent,
        on_round_timeout_vote,
        Some(payload_precheck.clone()),
    )?;

    produce::produce_loop::<R>(
        &db,
        &mempool,
        identity,
        &chain_lock,
        &finality_event_tx,
        &block_tx,
        &shutdown,
    )
}
