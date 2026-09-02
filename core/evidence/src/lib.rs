// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{info, warn};
use xc_artifact::{
    BlockAttestation, CanonicalHeader, DissentAttestation, EvidenceArtifact, Fault, ARTIFACT_VERSION,
};
use xc_mempool::Mempool;
use xc_primitives::{Action, Address, Block, SignatureError};
use xc_storage::ArxiumDb;

/// Whitepaper §9.3: double-sign slashes the full stake. Full BPS (10_000)
/// rather than a partial rate — equivocation is deliberate/attributable, so
/// the deterrent is maximal, unlike the graduated downtime rate
/// (`circuits/staking::DOWNTIME_SLASH_BPS`).
pub const EQUIVOCATION_SLASH_BPS: u128 = 10_000;

pub fn slash_amount(total_stake: u128) -> u128 {
    total_stake * EQUIVOCATION_SLASH_BPS / 10_000
}

/// Two blocks a validator signed for the same height — necessarily full
/// blocks, not a compact digest: `Block::sign` covers the entire action
/// list, so there's no smaller unit that still proves the signature.
pub struct EquivocationEvidence<P> {
    pub block_a: Block<P>,
    pub block_b: Block<P>,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("blocks are at different heights ({0} vs {1}), not equivocation")]
    HeightMismatch(u64, u64),
    #[error("blocks have different proposers, not equivocation")]
    ProposerMismatch,
    #[error("blocks are identical, not equivocation")]
    SameBlock,
    #[error("evidence block signature invalid: {0}")]
    Signature(#[from] SignatureError),
}

/// Checks both blocks are validly signed by the same proposer, at the same
/// height, with different content — the only way that's possible under
/// plain Ed25519 is the proposer having signed twice. Returns the offending
/// validator's address.
pub fn verify_equivocation<P: Serialize>(
    evidence: &EquivocationEvidence<P>,
) -> Result<Address, EvidenceError> {
    let a = &evidence.block_a;
    let b = &evidence.block_b;
    if a.height != b.height {
        return Err(EvidenceError::HeightMismatch(a.height, b.height));
    }
    let proposer_a = a.proposer.clone().ok_or(SignatureError::Missing)?;
    let proposer_b = b.proposer.clone().ok_or(SignatureError::Missing)?;
    if proposer_a != proposer_b {
        return Err(EvidenceError::ProposerMismatch);
    }
    if a.hash() == b.hash() {
        return Err(EvidenceError::SameBlock);
    }
    a.verify_proposer_signature()?;
    b.verify_proposer_signature()?;
    Ok(proposer_a)
}

/// Fed to `spawn_evidence_watcher` by `arxd/node`. `BlockObserved` signals a
/// block competing for an already-committed height (equivocation).
/// `ExecutionDisagreement` signals a block `arxd/node` itself rejected on
/// execution grounds, paired with the `Dissent` it signed and sent — built
/// by the caller (`arxd/finality` owns the `Dissent` type and its signing;
/// this crate only needs the already-signed, already-hex-encoded
/// `DissentAttestation` to write the artifact, so it doesn't need to depend
/// on `arxd/finality`).
pub enum EvidenceEvent<P> {
    BlockObserved(Block<P>),
    ExecutionDisagreement { proposed: Block<P>, dissent: DissentAttestation },
}

/// Builds a self-describing evidence artifact (see `xc_artifact`) from a
/// verified equivocation and writes it to
/// `<evidence_dir>/<height>-<proposer>.json`. Commits to a `CanonicalHeader`
/// + `signature` for each block — `verify()` recomputes the signing bytes
/// from the header rather than trusting anything this artifact merely
/// asserts, so `arx-verify` can check it without knowing `P` and without
/// trusting the artifact's author. The decoded blocks (including their
/// full hash) go under `human_readable` only.
fn write_equivocation_artifact<P: Serialize>(
    evidence_dir: &Path,
    genesis_hash: [u8; 32],
    proposer: &Address,
    evidence: &EquivocationEvidence<P>,
) {
    let attest = |block: &Block<P>| BlockAttestation {
        header: CanonicalHeader {
            height: block.height,
            parent_hash: block.parent_hash.clone(),
            timestamp: block.timestamp,
            tx_root: format!("0x{}", hex::encode(block.tx_root)),
            proposer: proposer.to_string(),
            state_root: block.state_root.clone(),
            round: block.round,
        },
        signature: format!("0x{}", block.signature.clone().unwrap_or_default()),
    };
    let proposer_pubkey = match proposer.pubkey_bytes() {
        Ok(bytes) => format!("0x{}", hex::encode(bytes)),
        Err(err) => {
            warn!("evidence: failed to encode proposer pubkey for artifact: {err}");
            return;
        }
    };

    let artifact = EvidenceArtifact {
        artifact_version: ARTIFACT_VERSION,
        genesis_hash: format!("0x{}", hex::encode(genesis_hash)),
        fault: Fault::Equivocation {
            proposer_pubkey,
            height: evidence.block_a.height,
            blocks: [attest(&evidence.block_a), attest(&evidence.block_b)],
        },
        human_readable: serde_json::json!({
            "block_a": evidence.block_a,
            "block_a_hash": evidence.block_a.hash(),
            "block_b": evidence.block_b,
            "block_b_hash": evidence.block_b.hash(),
        }),
    };

    if let Err(err) = std::fs::create_dir_all(evidence_dir) {
        warn!("evidence: failed to create evidence dir {}: {err}", evidence_dir.display());
        return;
    }
    let path = evidence_dir.join(format!("{}-{proposer}.json", evidence.block_a.height));
    match serde_json::to_vec_pretty(&artifact) {
        Ok(bytes) => {
            if let Err(err) = std::fs::write(&path, bytes) {
                warn!("evidence: failed to write artifact {}: {err}", path.display());
            } else {
                info!("evidence: wrote artifact {}", path.display());
            }
        }
        Err(err) => warn!("evidence: failed to encode artifact for {proposer}: {err}"),
    }
}

/// Builds and writes an `ExecutionDisagreement` artifact from a block
/// `arxd/node` rejected and the `Dissent` it signed over that rejection.
/// Unlike equivocation, `verify()` on this artifact can't name a culpable
/// party — see `xc_artifact::Verdict::Disagreement` — so this just records
/// that the dispute happened, to `<evidence_dir>/<height>-disagreement-<voter>.json`.
fn write_disagreement_artifact<P: Serialize>(
    evidence_dir: &Path,
    genesis_hash: [u8; 32],
    proposer: &Address,
    proposed: &Block<P>,
    dissent: &DissentAttestation,
) {
    let proposer_pubkey = match proposer.pubkey_bytes() {
        Ok(bytes) => format!("0x{}", hex::encode(bytes)),
        Err(err) => {
            warn!("evidence: failed to encode proposer pubkey for disagreement artifact: {err}");
            return;
        }
    };
    let attestation = BlockAttestation {
        header: CanonicalHeader {
            height: proposed.height,
            parent_hash: proposed.parent_hash.clone(),
            timestamp: proposed.timestamp,
            tx_root: format!("0x{}", hex::encode(proposed.tx_root)),
            proposer: proposer.to_string(),
            state_root: proposed.state_root.clone(),
            round: proposed.round,
        },
        signature: format!("0x{}", proposed.signature.clone().unwrap_or_default()),
    };

    let artifact = EvidenceArtifact {
        artifact_version: ARTIFACT_VERSION,
        genesis_hash: format!("0x{}", hex::encode(genesis_hash)),
        fault: Fault::ExecutionDisagreement {
            proposer_pubkey,
            height: proposed.height,
            proposed: attestation,
            dissent: dissent.clone(),
        },
        human_readable: serde_json::json!({
            "proposed": proposed,
            "proposed_hash": proposed.hash(),
        }),
    };

    if let Err(err) = std::fs::create_dir_all(evidence_dir) {
        warn!("evidence: failed to create evidence dir {}: {err}", evidence_dir.display());
        return;
    }
    let path = evidence_dir.join(format!("{}-disagreement-{}.json", proposed.height, dissent.voter));
    match serde_json::to_vec_pretty(&artifact) {
        Ok(bytes) => {
            if let Err(err) = std::fs::write(&path, bytes) {
                warn!("evidence: failed to write artifact {}: {err}", path.display());
            } else {
                info!("evidence: wrote artifact {}", path.display());
            }
        }
        Err(err) => warn!("evidence: failed to encode disagreement artifact for {proposer}: {err}"),
    }
}

/// Runs on its own thread, reacting to `events`. `build_evidence_action` is
/// `None` on a non-validator node — it still detects and logs equivocation,
/// it just has no funded/nonced account to sign a report with.
///
/// ponytail: `std::sync::mpsc` + blocking recv, not tokio — this loop does
/// no async I/O (just DB reads and a channel recv), so a dedicated tokio
/// runtime here would be needless machinery. Unlike `spawn_p2p_node`/
/// `spawn_http_ingest`, which do real async I/O and need one.
pub fn spawn_evidence_watcher<P, F>(
    db: ArxiumDb,
    mempool: Arc<Mutex<Mempool<P>>>,
    events: Receiver<EvidenceEvent<P>>,
    build_evidence_action: Option<F>,
    evidence_dir: PathBuf,
    genesis_hash: [u8; 32],
) -> thread::JoinHandle<()>
where
    P: Serialize + DeserializeOwned + Send + 'static,
    F: Fn(EquivocationEvidence<P>) -> Action<P> + Send + 'static,
{
    thread::spawn(move || {
        for event in events {
            let block = match event {
                EvidenceEvent::BlockObserved(block) => block,
                EvidenceEvent::ExecutionDisagreement { proposed, dissent } => {
                    let Some(proposer) = proposed.proposer.clone() else {
                        warn!(
                            "evidence: execution disagreement for unsigned block at height {}, skipping artifact",
                            proposed.height
                        );
                        continue;
                    };
                    write_disagreement_artifact(&evidence_dir, genesis_hash, &proposer, &proposed, &dissent);
                    continue;
                }
            };
            let existing: Option<Block<P>> = match db.get_block(block.height) {
                Ok(existing) => existing,
                Err(err) => {
                    warn!(
                        "evidence: failed to read stored block at height {}: {err}",
                        block.height
                    );
                    continue;
                }
            };
            let Some(existing) = existing else { continue };
            if existing.proposer != block.proposer || existing.hash() == block.hash() {
                continue;
            }

            let evidence = EquivocationEvidence { block_a: existing, block_b: block };
            let proposer = match verify_equivocation(&evidence) {
                Ok(proposer) => proposer,
                Err(err) => {
                    warn!("evidence: rejected equivocation evidence: {err}");
                    continue;
                }
            };
            match db.evidence_processed(evidence.block_a.height, &proposer) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    warn!("evidence: failed dedup check for {proposer}: {err}");
                    continue;
                }
            }

            // Independent of whether this node can sign a report: even a
            // non-validator observer should leave a durable, standalone
            // artifact that `arx-verify` can check later.
            write_equivocation_artifact(&evidence_dir, genesis_hash, &proposer, &evidence);

            let Some(build_evidence_action) = &build_evidence_action else {
                warn!("evidence: observed equivocation by {proposer}, no local validator key to report it");
                continue;
            };
            let action = build_evidence_action(evidence);
            let mut guard = mempool.lock().unwrap_or_else(|e| e.into_inner());
            match guard.push(action) {
                Ok(()) => info!("evidence: submitted equivocation evidence against {proposer}"),
                Err(err) => warn!("evidence: failed to submit equivocation evidence for {proposer}: {err}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signed_block(key: &SigningKey, height: u64, timestamp: u64) -> Block<()> {
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(timestamp);
        block.height = height;
        block.sign(addr, key);
        block
    }

    #[test]
    fn verify_equivocation_accepts_two_differently_hashed_blocks_same_height_and_proposer() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let block_a = signed_block(&key, 5, 100);
        let block_b = signed_block(&key, 5, 200);

        let proposer = verify_equivocation(&EquivocationEvidence { block_a, block_b }).unwrap();
        assert_eq!(proposer, Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap());
    }

    #[test]
    fn verify_equivocation_rejects_identical_blocks() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let block_a = signed_block(&key, 5, 100);
        let block_b = block_a.clone();

        let err = verify_equivocation(&EquivocationEvidence { block_a, block_b }).unwrap_err();
        assert!(matches!(err, EvidenceError::SameBlock));
    }

    #[test]
    fn verify_equivocation_rejects_different_proposers() {
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let block_a = signed_block(&key_a, 5, 100);
        let block_b = signed_block(&key_b, 5, 200);

        let err = verify_equivocation(&EquivocationEvidence { block_a, block_b }).unwrap_err();
        assert!(matches!(err, EvidenceError::ProposerMismatch));
    }

    #[test]
    fn verify_equivocation_rejects_different_heights() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let block_a = signed_block(&key, 5, 100);
        let block_b = signed_block(&key, 6, 200);

        let err = verify_equivocation(&EquivocationEvidence { block_a, block_b }).unwrap_err();
        assert!(matches!(err, EvidenceError::HeightMismatch(5, 6)));
    }

    #[test]
    fn verify_equivocation_rejects_a_forged_signature() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut block_a = signed_block(&key, 5, 100);
        let block_b = signed_block(&key, 5, 200);
        // Tamper after signing — signature no longer matches content.
        block_a.timestamp += 1;

        let err = verify_equivocation(&EquivocationEvidence { block_a, block_b }).unwrap_err();
        assert!(matches!(err, EvidenceError::Signature(_)));
    }

    /// Exercises the `ExecutionDisagreement` event path: `arxd/node` hands
    /// the watcher a block it rejected plus the `Dissent` it signed, and the
    /// watcher must write a disagreement artifact to disk (not touch the
    /// mempool — nobody is being slashed here).
    #[test]
    fn spawn_evidence_watcher_writes_disagreement_artifact() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-spawn-evidence-watcher-disagreement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let key = SigningKey::from_bytes(&[9u8; 32]);
        let proposed = signed_block(&key, 5, 100);
        let dissent = DissentAttestation {
            height: 5,
            block_hash: format!("0x{}", hex::encode(proposed.hash())),
            state_root: "0xdisputed".to_string(),
            header_commitment: format!("0x{}", hex::encode([4u8; 32])),
            ep: format!("0x{}", hex::encode([1u8; 32])),
            reason: "state_root_mismatch".to_string(),
            voter: "arx1voter".to_string(),
            voter_pubkey: format!("0x{}", hex::encode([2u8; 48])),
            signature: format!("0x{}", hex::encode([3u8; 96])),
        };

        let mempool: Arc<Mutex<Mempool<()>>> = Arc::new(Mutex::new(Mempool::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let build_evidence_action: Option<fn(EquivocationEvidence<()>) -> Action<()>> = None;
        let evidence_dir = dir.join("evidence");
        spawn_evidence_watcher(
            db.clone(),
            mempool.clone(),
            rx,
            build_evidence_action,
            evidence_dir.clone(),
            [7u8; 32],
        );

        tx.send(EvidenceEvent::ExecutionDisagreement { proposed: proposed.clone(), dissent }).unwrap();
        drop(tx);

        let path = evidence_dir.join(format!("{}-disagreement-arx1voter.json", proposed.height));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !path.exists() {
            assert!(std::time::Instant::now() < deadline, "disagreement artifact was never written");
            thread::sleep(std::time::Duration::from_millis(10));
        }

        let artifact: EvidenceArtifact = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(matches!(artifact.fault, Fault::ExecutionDisagreement { height: 5, .. }));
    }

    /// Exercises the same path `arxd/node`'s `on_block` triggers on a real
    /// competing gossiped block, minus the libp2p transport: stored block at
    /// the tip, a `BlockObserved` for a second block signed by the same
    /// proposer at that height, and confirms `spawn_evidence_watcher` both detects
    /// the equivocation and submits a signed report into the mempool.
    #[test]
    fn spawn_evidence_watcher_reports_observed_equivocation_into_mempool() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-spawn-evidence-watcher-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let key = SigningKey::from_bytes(&[9u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let stored = signed_block(&key, 5, 100);
        db.write_batches(&[&stored]).unwrap();

        let competing = signed_block(&key, 5, 200);

        let mempool: Arc<Mutex<Mempool<()>>> = Arc::new(Mutex::new(Mempool::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let build_evidence_action = Some(move |evidence: EquivocationEvidence<()>| Action {
            sender: evidence.block_a.proposer.clone().unwrap(),
            nonce: 0,
            signature: None,
            payload: (),
        });
        let evidence_dir = dir.join("evidence");
        spawn_evidence_watcher(
            db.clone(),
            mempool.clone(),
            rx,
            build_evidence_action,
            evidence_dir.clone(),
            [7u8; 32],
        );

        tx.send(EvidenceEvent::BlockObserved(competing)).unwrap();
        drop(tx);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if !mempool.lock().unwrap().is_empty() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "evidence watcher never submitted evidence action");
            thread::sleep(std::time::Duration::from_millis(10));
        }

        let reported = mempool.lock().unwrap().drain_pending(1);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].sender, addr);
        assert!(db.evidence_processed(5, &addr).unwrap_or(false) == false, "dedup marker is written by dispatch/apply_slash, not by the evidence subsystem itself");

        let artifact_path = evidence_dir.join(format!("5-{addr}.json"));
        let artifact: xc_artifact::EvidenceArtifact =
            serde_json::from_slice(&std::fs::read(&artifact_path).expect("artifact written to disk"))
                .expect("artifact is valid JSON");
        let verdict = xc_artifact::verify(&artifact).expect("artifact verifies standalone");
        match verdict {
            xc_artifact::Verdict::Culpable { culpable_pubkey, .. } => {
                assert_eq!(culpable_pubkey, format!("0x{}", hex::encode(key.verifying_key().as_bytes())));
            }
            other => panic!("expected Culpable verdict, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
