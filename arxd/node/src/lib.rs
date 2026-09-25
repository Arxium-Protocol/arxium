// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

mod cli;
mod commands;
mod components;
mod produce;
mod validator;

use crate::components::new_partial;
use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::Signer;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use xc_circuit::KeySpec as _;
use xc_runtime_api::ChainRuntime;

use arxd_finality::{
    Dissent, DissentReason, FinalityEvent, PEER_EVENT_BACKLOG_CAP, PrecommitEquivocation,
    PrecommitVote, RoundTimeoutVote, dissent_signing_bytes, spawn_finality,
};
use arxd_network::{P2pConfig, spawn_p2p_node};
use cli::{Cli, Command};
use commands::*;
use xc_artifact::{DissentAttestation, EvidenceArtifact, Fault, PrecommitAttestation};
use xc_evidence::{EquivocationEvidence, EvidenceEvent, spawn_evidence_watcher};
use xc_executor::{AcceptBlockError, accept_block};
use xc_mempool::Mempool;
#[cfg(test)]
use xc_primitives::Hash32;
use xc_primitives::{Action, Address, Block};
use xc_rpc::{IngestConfig, spawn_http_ingest};
use xc_storage::{ArxiumDb, DissentRecord};

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
            local: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
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
        let genesis = [1u8; 32];
        let header_commitment = [4u8; 32];
        let ep = [7u8; 32];
        assert_eq!(
            arxd_finality::dissent_signing_bytes(
                &genesis,
                5,
                "0xblock",
                "0xstate",
                &header_commitment,
                &ep,
                "state_root_mismatch"
            ),
            xc_artifact::dissent_signing_bytes(
                &genesis,
                5,
                "0xblock",
                "0xstate",
                &header_commitment,
                &ep,
                "state_root_mismatch"
            ),
        );
    }

    /// Same reasoning, for the precommit bytes `Fault::PrecommitEquivocation`
    /// recomputes: an artifact this node builds from two tallied votes is
    /// worthless if `xc-artifact` hashes a different message than the voter
    /// signed.
    #[test]
    fn precommit_signing_bytes_match_across_crates() {
        let genesis = [1u8; 32];
        let ep = [7u8; 32];
        assert_eq!(
            arxd_finality::precommit_signing_bytes(&genesis, 5, 0, "0xblock", &ep),
            xc_artifact::precommit_signing_bytes(&genesis, 5, 0, "0xblock", &ep),
        );
    }

    /// Same reasoning, for `xc_artifact::StateProof`'s duplicated sparse-Merkle
    /// hash functions (`sibling_leaf_hash`/`sibling_internal_hash`/
    /// `sibling_bit_at`) against `xc_poe::state_trie`'s canonical ones — a
    /// `Fault::ActionDivergence` proof this crate builds must verify with
    /// the exact hashes `xc-artifact` recomputes on the other end.
    #[test]
    fn action_divergence_hash_functions_match_across_crates() {
        let key_hash = [3u8; 32];
        let value = b"some account entry bytes";
        assert_eq!(
            xc_poe::state_trie::leaf_hash(&key_hash, value),
            xc_artifact::sibling_leaf_hash(&key_hash, value),
        );

        let left = [1u8; 32];
        let right = [2u8; 32];
        assert_eq!(
            xc_poe::state_trie::internal_hash(&left, &right),
            xc_artifact::sibling_internal_hash(&left, &right),
        );

        for level in [0usize, 1, 7, 8, 128, 255] {
            assert_eq!(
                xc_poe::state_trie::bit_at(&key_hash, level),
                xc_artifact::sibling_bit_at(&key_hash, level),
                "bit_at disagreed at level {level}",
            );
        }
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
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        (ArxiumDb::open(&dir).expect("open test db"), dir)
    }

    fn sample_record(height: u64, block_hash: Hash32, voter: Address) -> DissentRecord {
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
            previous_pubkey: None,
        }])
        .unwrap();

        let record = sample_record(5, block.hash(), voter.clone());
        let event = dissent_record_to_evidence_event::<()>(&db, record).expect(
            "a locally-held block with a registered voter key must yield an artifact event",
        );

        match event {
            EvidenceEvent::ExecutionDisagreement { proposed, dissent } => {
                assert_eq!(proposed.hash(), block.hash());
                assert_eq!(dissent.height, 5);
                assert_eq!(dissent.voter, voter.to_string());
                assert_eq!(dissent.reason, "state_root_mismatch");
            }
            EvidenceEvent::BlockObserved(_)
            | EvidenceEvent::BlockDivergence { .. }
            | EvidenceEvent::PrecommitEquivocation { .. } => {
                panic!("expected ExecutionDisagreement")
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_without_panicking_when_the_disputed_block_is_not_held_locally() {
        let (db, dir) = open_test_db();
        let voter = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let record = sample_record(5, Hash32::from_bytes([0xdd; 32]), voter);

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

/// Silence beyond which a skip stops being routine, in block intervals. A
/// slot is two intervals (one missed tick from jitter must not look like a
/// takeover), a full rotation is `validators` slots, so this many intervals
/// with nobody producing means it isn't simply someone else's turn — that is
/// the stall shape, and it escalates the log line from info to warn.
pub(crate) const STALL_SUSPECT_AFTER_INTERVALS: u64 = 20;

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
}

/// Turns a `DissentRecord` `arxd/finality` just persisted (whether signed
/// locally or received over gossip) into the `ExecutionDisagreement`
/// evidence event, by reading back the disputed block and the dissenter's
/// registered BLS key from local storage. Returns `None` (and lets the
/// caller decide whether to warn) when either read comes up empty — a node
/// that never received the disputed block has nothing to build a
/// `BlockAttestation` from, and synthesizing one from fields it didn't
/// actually read would turn the artifact into an unverified guess.
/// Nonce-stamps and signs a `SubmitExecutionFault` action for
/// `artifact_json`. Shared by the two fault kinds that reach the chain
/// through that action — a block divergence (after local re-adjudication)
/// and a precommit equivocation (which needs none).
fn sign_fault_action<R: ChainRuntime>(
    db: &ArxiumDb,
    address: &Address,
    key: &ed25519_dalek::SigningKey,
    artifact_json: String,
) -> Option<Action<R::Payload>> {
    let nonce = db
        .get_account(address)
        .ok()
        .flatten()
        .map(|entry| entry.nonce)
        .unwrap_or(0);
    let mut action = R::build_execution_fault_action(artifact_json, address, nonce)
        .expect("probed Some for this runtime at startup");
    let signature = key.sign(&action.signing_bytes());
    action.signature = Some(hex::encode(signature.to_bytes()));
    Some(action)
}

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
            warn!(
                "failed to read block at height {} for dissent evidence: {err}",
                record.height
            );
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
            warn!(
                "failed to read BLS key for dissenter {}: {err}",
                record.voter
            );
            return None;
        }
    };
    let attestation = DissentAttestation {
        height: record.height,
        block_hash: record.block_hash.to_string(),
        state_root: record.state_root,
        header_commitment: format!("0x{}", hex::encode(record.header_commitment)),
        ep: format!("0x{}", hex::encode(record.ep)),
        reason: record.reason,
        voter: record.voter.to_string(),
        voter_pubkey: format!("0x{}", hex::encode(voter_pubkey.0)),
        signature: format!("0x{}", hex::encode(record.signature.0)),
    };
    Some(EvidenceEvent::ExecutionDisagreement {
        proposed,
        dissent: attestation,
    })
}

/// Builds and sends the `Dissent` this node's BLS key can sign for an
/// execution disagreement, plus (when every touched key can still be proven
/// against the parent root) the stronger `BlockDivergence` fraud proof.
/// Pulled out of `on_block`'s rejection path in `spawn_subsystems`, which
/// nested this same logic 16 levels deep — same side effects, same early-
/// outs, just no longer indented past the point of reading it.
#[allow(clippy::too_many_arguments)]
fn dissent_on_execution_disagreement<R: ChainRuntime>(
    err: &AcceptBlockError,
    height: u64,
    candidate: &Block<R::Payload>,
    db: &ArxiumDb,
    genesis_hash: [u8; 32],
    address: &Address,
    bls_key: &xc_bls::BlsSecretKey,
    send_peer_event: &impl Fn(FinalityEvent<R::Payload>),
    dissent_tx: &tokio::sync::mpsc::UnboundedSender<Dissent>,
    evidence_tx: &std_mpsc::Sender<EvidenceEvent<R::Payload>>,
) {
    // Only these two variants should reach here — see
    // `AcceptBlockError::is_execution_disagreement`. That classifier lives in
    // a different crate than this match, though, so a future variant added
    // there without a matching arm here must not panic the block-handling
    // path: skip the dissent instead.
    let dissent_fields = match err {
        AcceptBlockError::StateRootMismatch {
            expected,
            touched_keys,
            ..
        } => Some((
            expected.clone(),
            DissentReason::StateRootMismatch,
            touched_keys.clone(),
        )),
        AcceptBlockError::ActionMismatch {
            local_state_root,
            touched_keys,
            ..
        } => Some((
            local_state_root.clone(),
            DissentReason::ActionMismatch,
            touched_keys.clone(),
        )),
        _ => {
            warn!(
                "is_execution_disagreement() true for a variant this match doesn't handle ({err}) — \
                 skipping dissent, not panicking"
            );
            None
        }
    };
    let Some((state_root, reason, touched_keys)) = dissent_fields else {
        return;
    };

    // A node that can't read its own parent stays quiet instead of signing a
    // dissent built on an EP it never actually read — same principle that
    // excludes `Storage` errors from `is_execution_disagreement` in the first
    // place. Ok(None) (genesis, no parent) is a legitimate empty EP, not a
    // read failure.
    let parent_state_root = match db.get_block::<R::Payload>(height.saturating_sub(1)) {
        Ok(Some(parent)) => parent.state_root,
        Ok(None) => String::new(),
        Err(err) => {
            warn!(
                "failed to read parent block {} for dissent EP — staying quiet instead of dissenting on \
                 unread data: {err}",
                height.saturating_sub(1)
            );
            return;
        }
    };
    let block_hash = candidate.hash();
    // Weight is a pure function of the action list, so this is what the
    // block *would* have used had it executed as claimed — the same sum the
    // proposer hashed into its EP.
    let weight_used = candidate.actions.iter().map(R::action_weight).sum();
    let ep = xc_poe::block_ep(
        &parent_state_root,
        &candidate.tx_root,
        &state_root,
        weight_used,
    );
    let proposer = candidate
        .proposer
        .as_ref()
        .expect("signature already verified, proposer present");
    let header_commitment: [u8; 32] = Sha256::digest(candidate.signing_bytes(proposer)).into();
    let msg = dissent_signing_bytes(
        &genesis_hash,
        height,
        &block_hash.to_string(),
        &state_root,
        &header_commitment,
        &ep,
        reason.as_str(),
    );
    let signature = xc_bls::sign(bls_key, &msg);
    let dissent = Dissent {
        height,
        block_hash,
        state_root: state_root.clone(),
        header_commitment,
        ep,
        reason,
        voter: address.clone(),
        signature,
    };
    send_peer_event(FinalityEvent::DissentObserved(dissent.clone()));
    let _ = dissent_tx.send(dissent.clone());
    let Ok(Some(pubkey)) = db.get_bls_pubkey(address) else {
        return;
    };

    let attestation = DissentAttestation {
        height: dissent.height,
        block_hash: dissent.block_hash.to_string(),
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

    // Alongside the plain dissent, try to build the stronger BlockDivergence
    // fraud proof: a proof per touched key against parent_state_root lets
    // arx-verify replay the block and name a culpable party instead of just
    // recording disagreement. Proving can fail (key pruned, db error) — that
    // just means no fraud proof this time, not a reason to skip the dissent
    // already sent above. Plus the two rows the adjudicator reads that
    // `dispatch` never touches through the view — the validator set is a
    // parameter, and it is located via `chain_params` — so a block with a
    // `LeaveValidator` can still be replayed.
    let mut touched_keys = touched_keys;
    let epoch_length = db
        .chain_params()
        .map(|p| p.epoch_length)
        .unwrap_or_default();
    touched_keys.push(xc_circuit::ChainParamsKey.encode());
    touched_keys.push(
        xc_circuit::ValidatorSetKey(xc_primitives::validator_set_effective_height(
            height,
            epoch_length,
        ))
        .encode(),
    );
    touched_keys.sort();
    touched_keys.dedup();
    let proofs: Result<Vec<xc_artifact::StateProof>, xc_storage::StorageError> = touched_keys
        .iter()
        .map(|key| {
            db.prove(key, &parent_state_root)
                .map(|proof| proof.into_state_proof())
        })
        .collect();
    match proofs {
        Ok(proofs) => {
            let claim_msg = xc_artifact::block_divergence_signing_bytes(
                &genesis_hash,
                height,
                &header_commitment,
                &parent_state_root,
                &state_root,
            );
            let claim_signature = xc_bls::sign(bls_key, &claim_msg);
            let dissent_claim = xc_artifact::BlockDissentClaim {
                computed_state_root: state_root.clone(),
                proofs,
                signature: format!("0x{}", hex::encode(claim_signature.0)),
            };
            let _ = evidence_tx.send(EvidenceEvent::BlockDivergence {
                proposed: candidate.clone(),
                parent_state_root: parent_state_root.clone(),
                voter: address.to_string(),
                voter_pubkey: format!("0x{}", hex::encode(pubkey.0)),
                dissent_claim,
            });
        }
        Err(err) => {
            warn!(
                "failed to prove a touched key for block divergence artifact — sending plain dissent only: {err}"
            );
        }
    }
}

/// The routine/not-routine, evidence-worthy classification `on_block`
/// applies to a rejected block — pulled out for the same reason as
/// `dissent_on_execution_disagreement` above.
fn handle_rejected_block<R: ChainRuntime>(
    err: &AcceptBlockError,
    height: u64,
    candidate: &Block<R::Payload>,
    db: &ArxiumDb,
    genesis_hash: [u8; 32],
    bls_identity: &Option<(Address, xc_bls::BlsSecretKey)>,
    send_peer_event: &impl Fn(FinalityEvent<R::Payload>),
    dissent_tx: &tokio::sync::mpsc::UnboundedSender<Dissent>,
    evidence_tx: &std_mpsc::Sender<EvidenceEvent<R::Payload>>,
) {
    // A block strictly behind our tip is an ordinary, expected race —
    // already applied via the other delivery path (gossip vs. sync) while
    // this one was in flight — not evidence of anything wrong, so it
    // doesn't deserve warn. Competing block for the height we already
    // committed (`block_height == tip_height`) is the one shape worth both
    // a warn and handing to the evidence watcher subsystem to check for
    // equivocation; anything else (ahead of tip, parent mismatch, bad
    // signature, etc.) stays at warn too.
    if is_routine_reject(err) {
        debug!("rejected gossiped block: {err}");
        return;
    }
    warn!("rejected gossiped block: {err}");
    if err.is_execution_disagreement() {
        if let Some((address, bls_key)) = bls_identity {
            dissent_on_execution_disagreement::<R>(
                err,
                height,
                candidate,
                db,
                genesis_hash,
                address,
                bls_key,
                send_peer_event,
                dissent_tx,
                evidence_tx,
            );
        }
    } else if matches!(
        err,
        AcceptBlockError::NotNextHeight { block_height, tip_height } if block_height == tip_height
    ) || matches!(err, AcceptBlockError::ContradictsCertificate { .. })
    {
        // Two shapes of the same sighting: a second block for a height
        // already committed, and a block for a height a quorum has
        // certified another block for (which is what reaches here once
        // the finality unwind has rolled the height back). Both are
        // equivocation-shaped and belong to the evidence watcher, not to
        // this path.
        let _ = evidence_tx.send(EvidenceEvent::BlockObserved(candidate.clone()));
    }
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
            EquivocationEvidence {
                block_a: dummy_block(),
                block_b: dummy_block(),
            },
            address,
            0,
        )?;

        let address = address.clone();
        let key = key.clone();
        let db = db.clone();
        Some(
            move |evidence: EquivocationEvidence<R::Payload>| -> Action<R::Payload> {
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
            },
        )
    });
    // Same probe-once-at-startup pattern as `build_evidence_action` above,
    // for `BlockDivergence` faults (see `ChainRuntime::build_execution_fault_action`).
    let build_execution_fault_action = identity.as_ref().and_then(|(address, key)| {
        R::build_execution_fault_action(String::new(), address, 0)?;

        let address = address.clone();
        let key = key.clone();
        let db = db.clone();
        Some(move |artifact: EvidenceArtifact| -> Option<Action<R::Payload>> {
            let artifact_json = serde_json::to_string(&artifact).expect("artifact always encodes");
            // A precommit equivocation is proved by its two signatures
            // alone, so there is no local re-adjudication to run and no
            // party to mistake for the culprit — the culpable key is the
            // one that signed both votes. It also needs no self-check: the
            // only way this node reports itself is if it genuinely
            // double-signed, which is exactly the fault being reported.
            if matches!(artifact.fault, Fault::PrecommitEquivocation { .. }) {
                return sign_fault_action::<R>(&db, &address, &key, artifact_json);
            }
            // The node writing this artifact is, by construction, the
            // dissenting party in it — if its own execution is the buggy
            // one, submitting unconditionally would name and slash itself.
            // Re-adjudicate locally (proof-backed replay, decoupled from
            // whatever live-execution path produced the dissent claim) and
            // only submit if it names someone else culpable.
            let culpable_pubkey = R::locally_adjudicate_execution_fault(&artifact_json)?;
            let voter_pubkey = match &artifact.fault {
                Fault::BlockDivergence { voter_pubkey, .. } => voter_pubkey,
                _ => return None,
            };
            if &culpable_pubkey == voter_pubkey {
                error!(
                    "evidence: local re-adjudication names this node itself as culpable for the block \
                     divergence it just reported — not submitting SubmitExecutionFault against ourselves \
                     (this points at a local execution bug, not the proposer)"
                );
                return None;
            }

            sign_fault_action::<R>(&db, &address, &key, artifact_json)
        })
    });
    spawn_supervised(
        "evidence",
        spawn_evidence_watcher(
            db.clone(),
            mempool.clone(),
            evidence_rx,
            build_evidence_action,
            build_execution_fault_action,
            config.base_path.join(chain_name).join("evidence"),
            genesis_hash,
        ),
    );

    // Finality subsystem's own message-passing seam: locally observed
    // blocks and peer precommit votes both funnel in as `FinalityEvent`s;
    // freshly-signed votes come back out on `finality_vote_rx` to be
    // gossiped over the network layer's precommit topic.
    let (finality_event_tx, finality_event_rx) = std_mpsc::channel::<FinalityEvent<R::Payload>>();
    let (finality_vote_tx, finality_vote_rx) = std_mpsc::channel::<PrecommitVote>();
    let (finality_round_timeout_tx, finality_round_timeout_rx) =
        std_mpsc::channel::<RoundTimeoutVote>();
    // Every dissent `spawn_finality` newly persists — whether signed
    // locally or received from a peer — comes back out here so it can be
    // turned into the same evidence artifact either way (see
    // `dissent_evidence_bridge` below). Closes the gap where only the
    // local-rejection path used to produce one.
    let (dissent_recorded_tx, dissent_recorded_rx) = std_mpsc::channel::<DissentRecord>();
    // Precommit equivocations `spawn_finality` detects while tallying, on
    // their way to the evidence watcher — same seam as `dissent_recorded_tx`
    // above, and for the same reason: `arxd/finality` owns the votes and
    // their signing, this crate owns the artifact shape.
    let (equivocation_tx, equivocation_rx) = std_mpsc::channel::<PrecommitEquivocation>();
    // `on_block` below also needs the BLS key to sign dissents on execution
    // disagreement, so clone before `spawn_finality` consumes the original.
    let bls_identity_for_dissent = bls_identity.clone();
    // Guards the read-tip / decide / write critical section shared by this
    // node's own production loop below, the gossip block-accept path, and
    // the finality thread's unwind when a certificate contradicts what this
    // node committed — so a self-produced block, a peer's gossiped block for
    // the same height, and a revert can never interleave. Whichever gets the
    // lock first wins, and the others observe the moved tip and back off.
    let chain_lock = Arc::new(Mutex::new(()));

    // Peer-sourced finality events are admitted through this counter — see
    // `PEER_EVENT_BACKLOG_CAP` for why the channel itself stays unbounded.
    let peer_backlog = Arc::new(AtomicUsize::new(0));
    let send_peer_event = {
        let finality_event_tx = finality_event_tx.clone();
        let peer_backlog = peer_backlog.clone();
        move |event: FinalityEvent<R::Payload>| {
            if peer_backlog.fetch_add(1, Ordering::Relaxed) >= PEER_EVENT_BACKLOG_CAP {
                peer_backlog.fetch_sub(1, Ordering::Relaxed);
                counter!("arxium_finality_peer_events_dropped_total").increment(1);
                return;
            }
            if finality_event_tx.send(event).is_err() {
                peer_backlog.fetch_sub(1, Ordering::Relaxed);
            }
        }
    };

    spawn_supervised(
        "finality",
        spawn_finality(
            db.clone(),
            bls_identity,
            finality_event_rx,
            finality_vote_tx,
            finality_round_timeout_tx,
            dissent_recorded_tx,
            equivocation_tx,
            chain_lock.clone(),
            peer_backlog,
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

    // Turns a detected double-signed precommit into the evidence event that
    // writes the artifact and reports it on-chain. The BLS key is read back
    // height-scoped (`get_bls_pubkey_at`), not current: the artifact must
    // carry the key the votes actually verify against, which a rotation
    // since would otherwise silently invalidate.
    spawn_supervised("precommit_equivocation_bridge", {
        let db = db.clone();
        let evidence_tx = evidence_tx.clone();
        thread::spawn(move || {
            for equivocation in equivocation_rx {
                let [a, b] = equivocation.votes;
                let Ok(Some(pubkey)) = db.get_bls_pubkey_at(&a.voter, a.height) else {
                    warn!(
                        "precommit equivocation by {} at height {} has no registered BLS key at that \
                         height, skipping evidence artifact",
                        a.voter, a.height
                    );
                    continue;
                };
                let attest = |vote: &PrecommitVote| PrecommitAttestation {
                    height: vote.height,
                    round: vote.round,
                    block_hash: vote.block_hash.to_string(),
                    ep: format!("0x{}", hex::encode(vote.ep)),
                    signature: format!("0x{}", hex::encode(vote.signature.0)),
                };
                let _ = evidence_tx.send(EvidenceEvent::<R::Payload>::PrecommitEquivocation {
                    voter: a.voter.clone(),
                    voter_pubkey: format!("0x{}", hex::encode(pubkey.0)),
                    height: a.height,
                    precommits: [attest(&a), attest(&b)],
                });
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
                // A halted node must not keep signing the chain it just
                // proved wrong; dropping the vote here is what "stops
                // voting" means in practice, and it takes effect at once
                // rather than at the produce loop's next tick.
                if arxd_network::shutdown_code() != 0 {
                    break;
                }
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
                if arxd_network::shutdown_code() != 0 {
                    break;
                }
                if round_timeout_tx.send(vote).is_err() {
                    break;
                }
            }
        }),
    );

    let on_precommit_vote: Box<dyn Fn(PrecommitVote) + Send> = {
        let send = send_peer_event.clone();
        Box::new(move |vote: PrecommitVote| send(FinalityEvent::VoteObserved(vote)))
    };

    let on_round_timeout_vote: Box<dyn Fn(RoundTimeoutVote) + Send> = {
        let send = send_peer_event.clone();
        Box::new(move |vote: RoundTimeoutVote| send(FinalityEvent::RoundTimeoutObserved(vote)))
    };

    let on_dissent: Box<dyn Fn(Dissent) + Send> = {
        let send = send_peer_event.clone();
        Box::new(move |dissent: Dissent| send(FinalityEvent::DissentObserved(dissent)))
    };

    let (dissent_tx, dissent_rx) = tokio::sync::mpsc::unbounded_channel::<Dissent>();

    // Shared between RPC submission and gossip receipt so a `JoinValidator`/
    // `LeaveValidator`/`RegisterBlsKey` that will actually be rejected by
    // `dispatch` gets rejected here instead, immediately and with a real
    // reason — see `ChainRuntime::admission_precheck`'s doc comment.
    let payload_precheck: xc_mempool::PayloadPrecheck<R::Payload> = Arc::new(R::admission_precheck);

    let (gossip_tx, gossip_rx) = tokio::sync::mpsc::unbounded_channel();
    spawn_http_ingest(IngestConfig {
        mempool: mempool.clone(),
        db: db.clone(),
        bind_addr: config.rpc_bind.clone(),
        port: config.port,
        rpc_token: config.rpc_token.clone(),
        admin_token: config.admin_token.clone(),
        gossip_tx: Some(gossip_tx),
        metrics_handle,
        payload_precheck: Some(payload_precheck.clone()),
        fee_hints: Some(xc_rpc::FeeHints {
            min_stake: R::min_validator_stake,
            action_fee_for: R::action_fee_for,
        }),
        evidence_dir: config.base_path.join(chain_name).join("evidence"),
        limits: config.limits.clone(),
    })?;

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
        // Own dissents go through the same gate as peer events so the
        // backlog counter's increments and decrements stay paired.
        let send_peer_event = send_peer_event.clone();
        let mempool = mempool.clone();
        let bls_identity = bls_identity_for_dissent.clone();
        let dissent_tx = dissent_tx.clone();
        Box::new(move |block: Block<R::Payload>, sync: bool| -> bool {
            let _guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());
            let height = block.height;
            let timestamp = block.timestamp;
            let candidate = block.clone();
            let params = match db.chain_params() {
                Ok(params) => params,
                Err(err) => {
                    tracing::error!(height, %err, "cannot read chain params, rejecting block");
                    return false;
                }
            };
            match accept_block(
                &db,
                block,
                sync,
                &crate::produce::meter::<R>(params),
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
                            timestamp,
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
                    handle_rejected_block::<R>(
                        &err,
                        height,
                        &candidate,
                        &db,
                        genesis_hash,
                        &bls_identity,
                        &send_peer_event,
                        &dissent_tx,
                        &evidence_tx,
                    );
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

    // ctrl-c is handled by the p2p runtime (`arxd_network::shutdown_code`);
    // nothing to spawn here.

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
    })
}

/// The one `chain_name` a fault-injection build is allowed to arm on. Not
/// the built-in `--chain devnet` preset — that preset's spec (`devnet.json`)
/// names itself `"corechain"` and its `boot_nodes` point at real public
/// IPs, so it's a shared network, not a local sandbox. A harness chain spec
/// must set `"chain_name": "arxium-fault-injection-harness"` explicitly, so
/// a mistyped `--chain` or a copy-pasted systemd unit can't ever satisfy
/// this by accident — anywhere else, this flag wouldn't be a test, it would
/// be a validator lying about its own state to real peers.
#[cfg(feature = "fault-injection")]
const FAULT_INJECTION_CHAIN_NAME: &str = "arxium-fault-injection-harness";

#[cfg(feature = "fault-injection")]
fn ensure_fault_injection_allowed(chain_name: &str) -> Result<()> {
    anyhow::ensure!(
        chain_name == FAULT_INJECTION_CHAIN_NAME,
        "fault injection requires chain_name {FAULT_INJECTION_CHAIN_NAME:?}, refusing to start on {chain_name:?}"
    );
    Ok(())
}

#[cfg(all(test, feature = "fault-injection"))]
mod fault_injection_tests {
    use super::{FAULT_INJECTION_CHAIN_NAME, ensure_fault_injection_allowed};

    #[test]
    fn the_harness_chain_name_is_allowed() {
        assert!(ensure_fault_injection_allowed(FAULT_INJECTION_CHAIN_NAME).is_ok());
    }

    #[test]
    fn anything_else_is_refused_including_the_real_devnet_preset() {
        assert!(ensure_fault_injection_allowed("mainnet").is_err());
        assert!(ensure_fault_injection_allowed("").is_err());
        // devnet.json's actual chain_name — must never pass.
        assert!(ensure_fault_injection_allowed("corechain").is_err());
    }
}

pub fn run<R: ChainRuntime>() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::NodeKey { base_path }) => return cmd_node_key(base_path),
        Some(Command::Keys {
            base_path,
            json,
            stake,
        }) => return cmd_keys(base_path, *json, *stake),
        Some(Command::ValidatorKey { base_path }) => return cmd_validator_key(base_path),
        Some(Command::BlsKey { base_path, qr, pop }) => return cmd_bls_key(base_path, *qr, *pop),
        Some(Command::Pair {
            base_path,
            node,
            token,
            revoke,
        }) => {
            return cmd_pair::<R>(base_path, node, token.as_deref(), *revoke);
        }
        Some(Command::Snapshot {
            base_path,
            chain,
            output,
        }) => {
            return cmd_snapshot::<R>(base_path, chain, output);
        }
        Some(Command::Prune {
            base_path,
            chain,
            retain_blocks,
        }) => {
            return cmd_prune::<R>(base_path, chain, *retain_blocks);
        }
        Some(Command::ChainInfo { chain, list }) => return cmd_chain_info::<R>(chain, *list),
        Some(Command::ChainSpec { chain }) => return cmd_chain_spec::<R>(chain),
        None => {}
    }

    run_node::<R>(cli)
}

/// No subcommand given: boot and run the node itself, same as always
/// (`arxd --validator ...`).
fn run_node<R: ChainRuntime>(cli: Cli) -> Result<()> {
    #[cfg(feature = "fault-injection")]
    let inject_fault_at_height = cli.run.inject_fault_at_height;
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

    #[cfg(feature = "fault-injection")]
    if let Some(height) = inject_fault_at_height {
        ensure_fault_injection_allowed(&chain_name)?;
        produce::INJECT_FAULT_AT_HEIGHT
            .set(height)
            .expect("set exactly once, before any block is produced");
        warn!(
            height,
            "FAULT INJECTION ARMED — this node will corrupt its own state_root when it \
             produces this height. Never use outside a devnet acceptance test."
        );
    }

    // Same guard as the fault flag above, for the same reason: this one
    // makes a validator refuse to talk to named peers, which outside a
    // harness is just a node silently cutting itself off from the network.
    // `build_swarm` reads the variable itself (arxd/network's
    // `partitioned_block_list`); this only decides whether the process is
    // allowed to boot with it set at all.
    #[cfg(feature = "fault-injection")]
    if let Ok(peers) = std::env::var("ARXD_BLOCK_PEERS")
        && !peers.trim().is_empty()
    {
        ensure_fault_injection_allowed(&chain_name)?;
        warn!(
            %peers,
            "PARTITION ARMED — this node refuses all connections to these peers. \
             Never use outside a devnet acceptance test."
        );
    }

    // Same guard again. Slowing the round timeout down is how the
    // partition harness makes its heal-during-voting window deterministic
    // (arxd/finality's `round_timeout`); on a real chain it would just be a
    // validator that tolerates a stalled round far longer than its peers do.
    #[cfg(feature = "fault-injection")]
    if let Ok(secs) = std::env::var("ARXD_ROUND_TIMEOUT_SECS")
        && !secs.trim().is_empty()
    {
        ensure_fault_injection_allowed(&chain_name)?;
        // Parsed here, on the main thread, so a typo refuses to boot. The
        // value is read lazily by a thread `spawn_finality` spawns, where
        // rejecting it is not an option: a panic there unwinds that thread
        // alone (no panic hook, no `panic = "abort"`), leaving a node that
        // still produces and gossips but has silently stopped voting and
        // tallying. Touching it here resolves it while a failure can still
        // be a clean startup error.
        if let Some(err) = arxd_finality::round_timeout_override_error() {
            anyhow::bail!(err);
        }
        warn!(
            %secs,
            "ROUND TIMEOUT OVERRIDDEN — this node waits this long before voting to \
             advance a round. Never use outside a devnet acceptance test."
        );
    }

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
    spawn_p2p_node(P2pConfig {
        base_path: &config.base_path,
        listen_port: config.p2p_port,
        bootnodes: &bootnodes,
        is_bootnode: config.is_bootnode,
        chain_id: &chain_id,
        mempool: mempool.clone(),
        db: db.clone(),
        gossip_rx,
        block_rx,
        precommit_rx,
        dissent_rx,
        round_timeout_rx,
        on_block: Box::new(on_block),
        on_precommit_vote: Box::new(on_precommit_vote),
        on_dissent: Box::new(on_dissent),
        on_round_timeout_vote: Box::new(on_round_timeout_vote),
        payload_precheck: Some(payload_precheck.clone()),
        limits: config.limits.clone(),
        snapshot_trust: config
            .snapshot_trust
            .clone()
            .map(|(height, block_hash)| {
                Ok::<_, xc_primitives::Hash32Error>(arxd_network::SnapshotTrust {
                    height,
                    block_hash: block_hash.parse()?,
                })
            })
            .transpose()
            .context("--snapshot-trust-hash is not a valid 32-byte hash")?,
    })?;

    produce::produce_loop::<R>(
        &db,
        &mempool,
        identity,
        &chain_lock,
        &finality_event_tx,
        &block_tx,
    )
}
