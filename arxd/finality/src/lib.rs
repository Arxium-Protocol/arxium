// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{info, warn};
use xc_bls::{BlsPublicKey, BlsSecretKey, BlsSignature};
use xc_primitives::{Address, Block, quorum, round_timeout_signing_bytes};
use xc_storage::{
    ArxiumDb, DissentRecord, FinalityRecord, PrecommitVoteRecord, RoundCertificate,
    RoundTimeoutVoteRecord,
};

// Domain tags, mixed into what gets signed, so a signature over a precommit
// can never be replayed as a dissent (or a round-timeout vote, or vice versa)
// even though they can share fields (height).
const DOMAIN_PRECOMMIT: &[u8] = b"arxium/precommit/v1";
const DOMAIN_DISSENT: &[u8] = b"arxium/dissent/v2";

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Exact bytes a validator signs for a precommit vote.
pub fn precommit_signing_bytes(height: u64, block_hash: &str, ep: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_PRECOMMIT);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, block_hash.as_bytes());
    push_field(&mut buf, ep);
    buf
}

/// Exact bytes a dissenting validator signs. Must match
/// `xc_artifact::dissent_signing_bytes` byte-for-byte — that crate can't
/// depend on this one, so it carries its own copy. Pinned by
/// `frozen_dissent_signing_bytes_vector` below, its twin in
/// `core/artifact/src/lib.rs`, and `dissent_signing_bytes_match_across_crates`
/// in `arxd/node/src/lib.rs` (the only crate that already depends on both),
/// mirroring `xc_artifact::signing_bytes_for` vs. `core/primitives`.
pub fn dissent_signing_bytes(
    height: u64,
    block_hash: &str,
    state_root: &str,
    header_commitment: &[u8; 32],
    ep: &[u8; 32],
    reason: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_DISSENT);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, block_hash.as_bytes());
    push_field(&mut buf, state_root.as_bytes());
    push_field(&mut buf, header_commitment);
    push_field(&mut buf, ep);
    push_field(&mut buf, reason.as_bytes());
    buf
}

/// Which kind of execution disagreement a `Dissent` reports — mirrors
/// `xc_executor::AcceptBlockError::is_execution_disagreement`'s two
/// dissent-worthy variants. `as_str()`'s output is what actually gets
/// signed/hashed (via `dissent_signing_bytes`) and persisted
/// (`DissentRecord::reason`), so it's the wire format — do not rename the
/// strings without a coordinated migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum DissentReason {
    StateRootMismatch,
    ActionMismatch,
}

impl DissentReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DissentReason::StateRootMismatch => "state_root_mismatch",
            DissentReason::ActionMismatch => "action_mismatch",
        }
    }
}

/// A validator's signed claim that it independently executed `block_hash`
/// at `height` and got `state_root`/`ep` instead of what the proposer
/// claimed. Gossiped over `arxd/network`'s dissent topic and fed into
/// `spawn_finality` on every node (including the dissenter's own), same
/// shape as `PrecommitVote`.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct Dissent {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    /// `sha256(signing_bytes_for(disputed block's header))` — binds this
    /// dissent to the exact block it disagrees with, since `block_hash`
    /// alone is an opaque chain-internal hash a verifier holding only the
    /// resulting evidence artifact can't recompute. See
    /// `xc_artifact::DissentAttestation::header_commitment`.
    pub header_commitment: [u8; 32],
    pub ep: [u8; 32],
    pub reason: DissentReason,
    pub voter: Address,
    pub signature: BlsSignature,
}

/// How many heights of unfinalized precommit tallies to keep.
///
/// `tallies` is in-process and was previously pruned only when a height
/// finalized, so any height that never reached quorum — a validator offline, a
/// vote lost in gossip, a stray vote for a competing hash — stayed for the
/// lifetime of the process. On a chain where quorum is unreachable at all (no
/// registered BLS keys, see `GET /finality`) that meant *every* height
/// accumulated forever.
///
/// Votes arrive within a few heights of the block they cover, so anything this
/// far behind the highest height seen is never going to gain another vote.
const TALLY_RETENTION_HEIGHTS: u64 = 500;

/// A vote is gossiped once, when this node signs it. If that one gossip
/// message never reaches enough peers, quorum can never be reached even
/// though the voter is alive and its vote is sitting right here — so
/// re-send this node's own not-yet-finalized votes on this cadence until
/// they're gone (finalized, or pruned by `TALLY_RETENTION_HEIGHTS`).
#[cfg(not(test))]
const VOTE_REBROADCAST_INTERVAL: Duration = Duration::from_secs(15);
// ponytail: short interval so the rebroadcast test doesn't sleep 15s.
#[cfg(test)]
const VOTE_REBROADCAST_INTERVAL: Duration = Duration::from_millis(50);

/// One validator's BLS-signed vote that it also attests to `block_hash` at
/// `height` — gossiped over `arxd/network`'s precommit topic and fed back
/// into `spawn_finality` on every node, including the signer's own.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct PrecommitVote {
    pub height: u64,
    pub block_hash: String,
    pub voter: Address,
    pub signature: BlsSignature,
    /// Execution proof this voter computed for the block — see
    /// `xc_poe::block_ep`. Tallied as part of the key (see `spawn_finality`'s
    /// `tallies`), so two votes agreeing on `block_hash` but disagreeing on
    /// `ep` never aggregate into the same quorum.
    pub ep: [u8; 32],
}

/// One validator's BLS-signed claim that `round` at `height` timed out with
/// no block produced — gossiped over `arxd/network`'s round-timeout topic
/// and fed back into `spawn_finality` on every node, including the signer's
/// own, same shape as `PrecommitVote`. Once a quorum of these for the same
/// `(height, round)` aggregate, `tally_round_timeout` persists a
/// `RoundCertificate`, which is what actually advances `eligible_proposer`'s
/// round — see `Arxium_OpenItems.md` §7 (B1b).
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct RoundTimeoutVote {
    pub height: u64,
    pub round: u32,
    pub voter: Address,
    pub signature: BlsSignature,
}

/// How long `spawn_finality` waits without the chain tip advancing before
/// signing a round-timeout vote for the current round of the next height.
///
/// Deliberately a standalone copy rather than importing `arxd/node`'s
/// `SLOT_DURATION`/`STALL_SUSPECT_AFTER`: `arxd/finality` is a lower layer
/// that `arxd/node` depends on, so the reverse import isn't available.
/// 8s is double `arxd/node::BLOCK_INTERVAL` (2s) — the same "one full slot"
/// reasoning `SLOT_DURATION` uses, kept in sync by convention since both
/// values are small, rarely-changed constants.
#[cfg(not(test))]
const ROUND_TIMEOUT: Duration = Duration::from_secs(8);
// ponytail: short interval so timeout-triggering tests don't sleep 8s.
#[cfg(test)]
const ROUND_TIMEOUT: Duration = Duration::from_millis(150);

/// Fed to `spawn_finality`: either a block this node just accepted/produced
/// (triggers signing a precommit, if this node has a BLS identity, and
/// resets the round-timeout clock below), a precommit vote received from a
/// peer (tallied toward quorum), a dissent (verified, tallied one-per-voter,
/// and persisted — but never contributes to a precommit quorum; see
/// `handle_dissent`), or a round-timeout vote received from a peer (tallied
/// toward a `RoundCertificate`; see `tally_round_timeout`).
pub enum FinalityEvent<P> {
    BlockObserved(Block<P>),
    VoteObserved(PrecommitVote),
    DissentObserved(Dissent),
    RoundTimeoutObserved(RoundTimeoutVote),
}

/// Runs on its own thread. `bls_identity` is `Some((address, secret_key))`
/// on a node that holds a registered BLS key — it still tallies and
/// finalizes without one, it just can't contribute a vote. `vote_tx` is
/// where freshly-signed precommits go out to be gossiped; `round_timeout_tx`
/// is the same for round-timeout votes; `events` carries locally-observed
/// blocks and incoming peer votes/dissents/round-timeouts. `dissent_tx` gets
/// a copy of every dissent this node newly persists (whether it originated
/// locally or arrived from a peer) — `arxd/node` uses it to emit the same
/// evidence artifact for both paths, see `xc_evidence::EvidenceEvent`.
pub fn spawn_finality<P>(
    db: ArxiumDb,
    bls_identity: Option<(Address, BlsSecretKey)>,
    events: Receiver<FinalityEvent<P>>,
    vote_tx: Sender<PrecommitVote>,
    round_timeout_tx: Sender<RoundTimeoutVote>,
    dissent_tx: Sender<DissentRecord>,
) -> thread::JoinHandle<()>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    thread::spawn(move || {
        // height -> ((block_hash, ep) -> (voter -> signature)); a height can
        // only ever have one canonical (hash, ep) pair in practice, but keyed
        // this way a stray vote for a competing hash or a diverging ep can't
        // corrupt the real tally.
        let mut tallies: HashMap<u64, HashMap<(String, [u8; 32]), HashMap<Address, BlsSignature>>> = HashMap::new();

        // This node's own not-yet-finalized votes, kept so they can be
        // re-sent on VOTE_REBROADCAST_INTERVAL — see the constant's doc.
        let mut my_votes: HashMap<u64, PrecommitVote> = HashMap::new();

        // (height, round) -> voter -> signature; mirrors `tallies` above but
        // keyed by round too, since more than one round of a single height
        // can be mid-tally at once (an earlier round's stragglers arriving
        // after a later round already got certified).
        let mut round_timeout_tallies: HashMap<(u64, u32), HashMap<Address, BlsSignature>> = HashMap::new();
        // This node's own not-yet-certified round-timeout votes — mirrors
        // `my_votes`.
        let mut my_round_timeout_votes: HashMap<(u64, u32), RoundTimeoutVote> = HashMap::new();
        // (highest height with a block observed, when it was observed) —
        // the round-timeout clock: if this stays untouched for
        // `ROUND_TIMEOUT`, this node signs a round-timeout vote for the
        // current round of the next height. Starts at "now" rather than a
        // zero `Instant` so a freshly-started node gets one full
        // `ROUND_TIMEOUT` of grace before it starts accusing round 0 of the
        // chain's very first height.
        let mut last_progress: (u64, Instant) = (0, Instant::now());

        // Highest height seen from either event kind, used as the pruning
        // watermark below.
        let mut highest_seen: u64 = 0;

        // Reload whatever partial tallies survived a restart — a crash after
        // a vote landed but before quorum used to silently drop it. Two
        // passes: read everything persisted, find the true watermark, then
        // keep only what's still within the retention window (mirrors the
        // per-event pruning below, which will also delete anything stale
        // this leaves behind).
        match db.get_precommit_votes_from(0) {
            Ok(records) => {
                highest_seen = records.iter().map(|r| r.height).max().unwrap_or(0);
                let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
                for record in records {
                    if record.height < cutoff {
                        continue;
                    }
                    tallies
                        .entry(record.height)
                        .or_default()
                        .entry((record.block_hash, record.ep))
                        .or_default()
                        .insert(record.voter, record.signature);
                }
            }
            Err(err) => warn!("finality: failed to reload persisted precommit votes: {err}"),
        }

        // Dissents don't feed any in-memory structure (one-per-voter is
        // enforced by a direct `db.get_dissent` read on each new one, not an
        // in-memory set) — reloading them just brings the pruning watermark
        // up to date, so a restart right after a dissent at a height beyond
        // any tallied vote doesn't leave it un-prunable.
        match db.get_dissents_from(0) {
            Ok(records) => {
                highest_seen = highest_seen.max(records.iter().map(|r| r.height).max().unwrap_or(0));
            }
            Err(err) => warn!("finality: failed to reload persisted dissents: {err}"),
        }

        match db.get_round_timeout_votes_from(0) {
            Ok(records) => {
                highest_seen = highest_seen.max(records.iter().map(|r| r.height).max().unwrap_or(0));
                let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
                for record in records {
                    if record.height < cutoff {
                        continue;
                    }
                    round_timeout_tallies
                        .entry((record.height, record.round))
                        .or_default()
                        .insert(record.voter, record.signature);
                }
            }
            Err(err) => warn!("finality: failed to reload persisted round-timeout votes: {err}"),
        }

        loop {
            let event = match events.recv_timeout(VOTE_REBROADCAST_INTERVAL) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => {
                    for vote in my_votes.values() {
                        if vote_tx.send(vote.clone()).is_err() {
                            warn!("finality: vote channel closed, stopping");
                            return;
                        }
                    }
                    for vote in my_round_timeout_votes.values() {
                        if round_timeout_tx.send(vote.clone()).is_err() {
                            warn!("finality: round-timeout vote channel closed, stopping");
                            return;
                        }
                    }
                    if let Some((address, secret_key)) = &bls_identity {
                        if last_progress.1.elapsed() >= ROUND_TIMEOUT {
                            let next_height = last_progress.0 + 1;
                            match db.current_round(next_height) {
                                Ok(round) => {
                                    let already_certified =
                                        matches!(db.get_round_certificate(next_height, round), Ok(Some(_)));
                                    if !already_certified
                                        && !my_round_timeout_votes.contains_key(&(next_height, round))
                                    {
                                        match db.get_block::<P>(next_height.saturating_sub(1)) {
                                            Ok(Some(parent)) => {
                                                let msg = round_timeout_signing_bytes(
                                                    next_height,
                                                    round,
                                                    &parent.hash(),
                                                );
                                                let signature = xc_bls::sign(secret_key, &msg);
                                                let vote = RoundTimeoutVote {
                                                    height: next_height,
                                                    round,
                                                    voter: address.clone(),
                                                    signature,
                                                };
                                                my_round_timeout_votes
                                                    .insert((vote.height, vote.round), vote.clone());

                                                // Same local-loopback rule as
                                                // precommit votes: tally our own
                                                // timeout vote before gossip.
                                                if let Err(err) = tally_round_timeout::<P>(
                                                    &db,
                                                    &mut round_timeout_tallies,
                                                    &mut my_round_timeout_votes,
                                                    vote.clone(),
                                                ) {
                                                    warn!(
                                                        "finality: failed to process local round-timeout vote: {err}"
                                                    );
                                                }

                                                if round_timeout_tx.send(vote).is_err() {
                                                    warn!(
                                                        "finality: round-timeout vote channel closed, stopping"
                                                    );
                                                    return;
                                                }
                                            }
                                            Ok(None) => warn!(
                                                "finality: no parent block at height {} to sign a round-timeout vote against",
                                                next_height.saturating_sub(1)
                                            ),
                                            Err(err) => warn!(
                                                "finality: failed to read parent block at height {}: {err}",
                                                next_height.saturating_sub(1)
                                            ),
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("finality: failed to read current round for height {next_height}: {err}")
                                }
                            }
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => return,
            };

            highest_seen = highest_seen.max(match &event {
                FinalityEvent::BlockObserved(block) => block.height,
                FinalityEvent::VoteObserved(vote) => vote.height,
                FinalityEvent::DissentObserved(dissent) => dissent.height,
                FinalityEvent::RoundTimeoutObserved(vote) => vote.height,
            });
            if let FinalityEvent::BlockObserved(block) = &event {
                if block.height > last_progress.0 {
                    last_progress = (block.height, Instant::now());
                }
            }
            // Bounded on every event rather than only on finalization, which
            // is the case that may never come.
            let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
            for height in tallies.keys().copied().filter(|h| *h < cutoff).collect::<Vec<_>>() {
                if let Err(err) = db.delete_precommit_votes(height) {
                    warn!("finality: failed to prune persisted precommit votes for height {height}: {err}");
                }
                // Dissents are deliberately *not* pruned on this schedule — see
                // `TALLY_RETENTION_HEIGHTS`'s doc: that bound is justified for
                // votes because an unfinalized height is never going to gain
                // another one. A dissent is different — it's a signed claim a
                // fault occurred, and heights that never finalize are exactly
                // where dissents live (disagreement is often *why* quorum
                // wasn't reached). Dissent volume on a healthy chain is ~zero,
                // so unbounded retention isn't the unbounded-growth risk that
                // motivated pruning votes in the first place.
            }
            tallies.retain(|height, _| *height >= cutoff);
            my_votes.retain(|height, _| *height >= cutoff);
            for key in round_timeout_tallies.keys().copied().filter(|(h, _)| *h < cutoff).collect::<Vec<_>>() {
                if let Err(err) = db.delete_round_timeout_votes(key.0, key.1) {
                    warn!(
                        "finality: failed to prune persisted round-timeout votes for height {} round {}: {err}",
                        key.0, key.1
                    );
                }
            }
            round_timeout_tallies.retain(|(height, _), _| *height >= cutoff);
            my_round_timeout_votes.retain(|(height, _), _| *height >= cutoff);

            match event {
                FinalityEvent::BlockObserved(block) => {
                    let Some((address, secret_key)) = &bls_identity else { continue };
                    let hash = block.hash();
                    // ponytail: parent lookup failure (or genesis) falls back
                    // to an empty parent state root rather than dropping the
                    // vote — EP mismatches from that are self-consistent
                    // (every honest node hits the same fallback), so quorum
                    // still forms; only an actually-diverging EP should ever
                    // block it.
                    let parent_state_root = match db.get_block::<P>(block.height.saturating_sub(1)) {
                        Ok(Some(parent)) => parent.state_root,
                        Ok(None) => String::new(),
                        Err(err) => {
                            warn!("finality: failed to read parent block for EP at height {}: {err}", block.height);
                            String::new()
                        }
                    };
                    let ep = xc_poe::block_ep(&parent_state_root, &block.tx_root, &block.state_root);
                    let msg = precommit_signing_bytes(block.height, &hash, &ep);
                    let signature = xc_bls::sign(secret_key, &msg);
                    let vote =
                        PrecommitVote { height: block.height, block_hash: hash, voter: address.clone(), signature, ep };
                    my_votes.insert(vote.height, vote.clone());

                    // Count our own signed vote locally before gossiping it.
                    // Gossipsub publication is not a local loopback mechanism,
                    // so waiting for VoteObserved would leave every validator
                    // counting only its peers' votes.
                    if let Err(err) =
                        tally_vote(&db, &mut tallies, &mut my_votes, vote.clone())
                    {
                        warn!("finality: failed to process local precommit vote: {err}");
                    }

                    if vote_tx.send(vote).is_err() {
                        warn!("finality: vote channel closed, stopping");
                        return;
                    }
                }
                FinalityEvent::VoteObserved(vote) => {
                    if let Err(err) = tally_vote(&db, &mut tallies, &mut my_votes, vote) {
                        warn!("finality: failed to process precommit vote: {err}");
                    }
                }
                FinalityEvent::DissentObserved(dissent) => {
                    if let Err(err) = handle_dissent(&db, dissent, &dissent_tx) {
                        warn!("finality: failed to process dissent: {err}");
                    }
                }
                FinalityEvent::RoundTimeoutObserved(vote) => {
                    if let Err(err) = tally_round_timeout::<P>(
                        &db,
                        &mut round_timeout_tallies,
                        &mut my_round_timeout_votes,
                        vote,
                    ) {
                        warn!("finality: failed to process round-timeout vote: {err}");
                    }
                }
            }
        }
    })
}

fn tally_vote(
    db: &ArxiumDb,
    tallies: &mut HashMap<u64, HashMap<(String, [u8; 32]), HashMap<Address, BlsSignature>>>,
    my_votes: &mut HashMap<u64, PrecommitVote>,
    vote: PrecommitVote,
) -> Result<(), xc_storage::StorageError> {
    if db.get_finality_record(vote.height)?.is_some() {
        return Ok(()); // already finalized, nothing left to tally
    }

    // Height-scoped, not `get_bls_pubkey` (the current key): this vote may
    // be tallied long after it was signed, and this record is later
    // replayed as-is by any node syncing this height — it must verify
    // against the key that was valid when the vote was cast, not whatever
    // the voter has rotated to since. See `ArxiumDb::get_bls_pubkey_at`.
    let Some(pubkey) = db.get_bls_pubkey_at(&vote.voter, vote.height)? else {
        warn!("finality: vote from {} with no registered BLS key, dropping", vote.voter);
        return Ok(());
    };
    let msg = precommit_signing_bytes(vote.height, &vote.block_hash, &vote.ep);
    if xc_bls::verify(&msg, &pubkey, &vote.signature).is_err() {
        warn!("finality: dropping vote from {} with an invalid signature", vote.voter);
        return Ok(());
    }

    let validators = db.get_validator_set_at(vote.height)?;
    if !validators.contains(&vote.voter) {
        warn!("finality: dropping vote from {}, not a validator at height {}", vote.voter, vote.height);
        return Ok(());
    }

    let vote_record = PrecommitVoteRecord {
        height: vote.height,
        block_hash: vote.block_hash.clone(),
        voter: vote.voter.clone(),
        signature: vote.signature.clone(),
        ep: vote.ep,
    };

    let signers = tallies
        .entry(vote.height)
        .or_default()
        .entry((vote.block_hash.clone(), vote.ep))
        .or_default();
    signers.insert(vote.voter, vote.signature);

    // Persisted before the quorum check so a crash between this vote and
    // reaching quorum still leaves it recoverable on restart.
    db.write_batches(&[&vote_record])?;

    if signers.len() < quorum(validators.len()) {
        return Ok(());
    }

    let pubkeys: Vec<BlsPublicKey> = signers
        .keys()
        .filter_map(|addr| db.get_bls_pubkey_at(addr, vote.height).ok().flatten())
        .collect();
    let sigs: Vec<BlsSignature> = signers.values().cloned().collect();
    let Ok(aggregate_signature) = xc_bls::aggregate(&sigs) else {
        warn!("finality: failed to aggregate signatures for height {}", vote.height);
        return Ok(());
    };
    if xc_bls::verify_aggregate(&msg, &pubkeys, &aggregate_signature).is_err() {
        warn!("finality: aggregate signature failed to verify for height {}", vote.height);
        return Ok(());
    }

    let record = FinalityRecord {
        height: vote.height,
        block_hash: vote.block_hash.clone(),
        signers: signers.keys().cloned().collect(),
        aggregate_signature,
    };
    db.write_batches(&[&record])?;
    if let Err(err) = db.delete_precommit_votes(vote.height) {
        warn!("finality: failed to delete persisted precommit votes for finalized height {}: {err}", vote.height);
    }
    tallies.remove(&vote.height);
    my_votes.remove(&vote.height);
    info!("finality: block {} finalized with {} signers", vote.height, record.signers.len());
    Ok(())
}

/// Mirrors `tally_vote` exactly, but for round-timeout votes: verifies
/// signature and validator membership, persists the vote, and once a
/// quorum for `(height, round)` is reached, aggregates and persists a
/// `RoundCertificate` — which is what actually makes `round + 1` eligible
/// (see `xc_storage::ArxiumDb::current_round`).
fn tally_round_timeout<P: Serialize + DeserializeOwned>(
    db: &ArxiumDb,
    tallies: &mut HashMap<(u64, u32), HashMap<Address, BlsSignature>>,
    my_votes: &mut HashMap<(u64, u32), RoundTimeoutVote>,
    vote: RoundTimeoutVote,
) -> Result<(), xc_storage::StorageError> {
    if db.get_round_certificate(vote.height, vote.round)?.is_some() {
        return Ok(()); // already certified, nothing left to tally
    }

    let Some(parent) = db.get_block::<P>(vote.height.saturating_sub(1))? else {
        warn!(
            "finality: round-timeout vote for height {} with no local parent block at {}, dropping",
            vote.height,
            vote.height.saturating_sub(1)
        );
        return Ok(());
    };

    let Some(pubkey) = db.get_bls_pubkey_at(&vote.voter, vote.height)? else {
        warn!("finality: round-timeout vote from {} with no registered BLS key, dropping", vote.voter);
        return Ok(());
    };
    let msg = round_timeout_signing_bytes(vote.height, vote.round, &parent.hash());
    if xc_bls::verify(&msg, &pubkey, &vote.signature).is_err() {
        warn!("finality: dropping round-timeout vote from {} with an invalid signature", vote.voter);
        return Ok(());
    }

    let validators = db.get_validator_set_at(vote.height)?;
    if !validators.contains(&vote.voter) {
        warn!(
            "finality: dropping round-timeout vote from {}, not a validator at height {}",
            vote.voter, vote.height
        );
        return Ok(());
    }

    let vote_record = RoundTimeoutVoteRecord {
        height: vote.height,
        round: vote.round,
        voter: vote.voter.clone(),
        signature: vote.signature.clone(),
    };

    let key = (vote.height, vote.round);
    let signers = tallies.entry(key).or_default();
    signers.insert(vote.voter, vote.signature);

    // Persisted before the quorum check so a crash between this vote and
    // reaching quorum still leaves it recoverable on restart.
    db.write_batches(&[&vote_record])?;

    if signers.len() < quorum(validators.len()) {
        return Ok(());
    }

    let pubkeys: Vec<BlsPublicKey> = signers
        .keys()
        .filter_map(|addr| db.get_bls_pubkey_at(addr, vote.height).ok().flatten())
        .collect();
    let sigs: Vec<BlsSignature> = signers.values().cloned().collect();
    let Ok(aggregate_signature) = xc_bls::aggregate(&sigs) else {
        warn!("finality: failed to aggregate round-timeout signatures for height {} round {}", vote.height, vote.round);
        return Ok(());
    };
    if xc_bls::verify_aggregate(&msg, &pubkeys, &aggregate_signature).is_err() {
        warn!(
            "finality: aggregate round-timeout signature failed to verify for height {} round {}",
            vote.height, vote.round
        );
        return Ok(());
    }

    let record = RoundCertificate {
        height: vote.height,
        round: vote.round,
        signers: signers.keys().cloned().collect(),
        aggregate_signature,
    };
    db.write_batches(&[&record])?;
    if let Err(err) = db.delete_round_timeout_votes(vote.height, vote.round) {
        warn!(
            "finality: failed to delete persisted round-timeout votes for certified height {} round {}: {err}",
            vote.height, vote.round
        );
    }
    tallies.remove(&key);
    my_votes.remove(&key);
    info!("finality: round {} at height {} certified as timed out with {} signers", vote.round, vote.height, record.signers.len());
    Ok(())
}

/// Verifies a dissent's signature and validator membership, enforces one
/// dissent per (height, voter) against what's already persisted, and — if
/// it's new — persists it, bumps `arxium_dissent_total{reason}`, and hands
/// a copy to `dissent_tx` so `arxd/node` can emit an evidence artifact for
/// it (see `spawn_finality`'s doc). Never touches `tallies`: a dissent is
/// not a precommit vote and never contributes to quorum, it's only
/// recorded as evidence.
fn handle_dissent(
    db: &ArxiumDb,
    dissent: Dissent,
    dissent_tx: &Sender<DissentRecord>,
) -> Result<(), xc_storage::StorageError> {
    if db.get_finality_record(dissent.height)?.is_some() {
        return Ok(()); // already finalized; a late dissent proves nothing new
    }

    let Some(pubkey) = db.get_bls_pubkey_at(&dissent.voter, dissent.height)? else {
        warn!("finality: dissent from {} with no registered BLS key, dropping", dissent.voter);
        return Ok(());
    };
    let reason = dissent.reason.as_str();
    let msg = dissent_signing_bytes(
        dissent.height,
        &dissent.block_hash,
        &dissent.state_root,
        &dissent.header_commitment,
        &dissent.ep,
        reason,
    );
    if xc_bls::verify(&msg, &pubkey, &dissent.signature).is_err() {
        warn!("finality: dropping dissent from {} with an invalid signature", dissent.voter);
        return Ok(());
    }

    let validators = db.get_validator_set_at(dissent.height)?;
    if !validators.contains(&dissent.voter) {
        warn!("finality: dropping dissent from {}, not a validator at height {}", dissent.voter, dissent.height);
        return Ok(());
    }

    if db.get_dissent(dissent.height, &dissent.voter)?.is_some() {
        warn!("finality: dropping duplicate dissent from {} at height {}", dissent.voter, dissent.height);
        return Ok(());
    }

    let record = DissentRecord {
        height: dissent.height,
        block_hash: dissent.block_hash,
        state_root: dissent.state_root,
        header_commitment: dissent.header_commitment,
        ep: dissent.ep,
        reason: reason.to_string(),
        voter: dissent.voter,
        signature: dissent.signature,
    };
    db.write_batches(&[&record])?;
    metrics::counter!("arxium_dissent_total", "reason" => reason).increment(1);
    info!("finality: recorded dissent from {} at height {} ({reason})", record.voter, record.height);
    let _ = dissent_tx.send(record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::mpsc;

    fn signed_block(key: &SigningKey, height: u64, timestamp: u64) -> Block<()> {
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(timestamp);
        block.height = height;
        block.sign(addr, key);
        block
    }

    fn open_test_db() -> (ArxiumDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-finality-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        (ArxiumDb::open(&dir).expect("open test db"), dir)
    }

    /// Pins `dissent_signing_bytes`'s exact output against a hardcoded hex
    /// vector, twinned with `frozen_dissent_signing_bytes_vector` in
    /// `core/artifact/src/lib.rs`. If either crate's encoding drifts from
    /// the other, one of the two copies fails loudly instead of silently —
    /// every previously-issued disagreement artifact would otherwise
    /// quietly stop verifying. `dissent_signing_bytes_match_across_crates`
    /// in `arxd/node/src/lib.rs` covers the same invariant directly (that
    /// crate depends on both), but a frozen vector also catches a drift
    /// where both crates change in lockstep to the same *wrong* answer.
    #[test]
    fn frozen_dissent_signing_bytes_vector() {
        let bytes = dissent_signing_bytes(
            5,
            "0xblockhash",
            "0xstateroot",
            &[9u8; 32],
            &[7u8; 32],
            "state_root_mismatch",
        );
        assert_eq!(
            hex::encode(&bytes),
            "110000000000000061727869756d2f64697373656e742f7632080000000000000005000000000000000b000000000000003078626c6f636b686173680b0000000000000030787374617465726f6f742000000000000000090909090909090909090909090909090909090909090909090909090909090920000000000000000707070707070707070707070707070707070707070707070707070707070707130000000000000073746174655f726f6f745f6d69736d61746368",
        );
    }

    #[test]
    fn quorum_is_two_thirds_plus_one() {
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(3), 3);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(7), 5);
    }

    #[test]
    fn no_finality_record_below_quorum_then_one_appears_at_quorum() {
        let (db, dir) = open_test_db();
        let addrs_and_keys: Vec<(Address, BlsSecretKey)> = (0u8..4)
            .map(|i| {
                let ed_key = SigningKey::from_bytes(&[i + 1; 32]);
                let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
                let (sk, pk) = xc_bls::keygen_from_seed(&[i + 50; 32]).unwrap();
                db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
                (addr, sk)
            })
            .collect();
        let validators: Vec<Address> = addrs_and_keys.iter().map(|(a, _)| a.clone()).collect();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot {
            effective_height: 0,
            validators: validators.clone(),
        }])
        .unwrap();

        let block_hash = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100).hash();
        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();

        let ep = [1u8; 32];

        // 3 of 4 validators is quorum() == 3; first two votes shouldn't finalize.
        for (addr, sk) in addrs_and_keys.iter().take(2) {
            let vote = PrecommitVote {
                height: 5,
                block_hash: block_hash.clone(),
                voter: addr.clone(),
                signature: xc_bls::sign(sk, &precommit_signing_bytes(5, &block_hash, &ep)),
                ep,
            };
            tally_vote(&db, &mut tallies, &mut my_votes, vote).unwrap();
            assert!(db.get_finality_record(5).unwrap().is_none());
        }

        let (addr, sk) = &addrs_and_keys[2];
        let vote = PrecommitVote {
            height: 5,
            block_hash: block_hash.clone(),
            voter: addr.clone(),
            signature: xc_bls::sign(sk, &precommit_signing_bytes(5, &block_hash, &ep)),
            ep,
        };
        tally_vote(&db, &mut tallies, &mut my_votes, vote).unwrap();

        let record = db.get_finality_record(5).unwrap().expect("expected finality record at quorum");
        assert_eq!(record.signers.len(), 3);
        assert_eq!(record.block_hash, block_hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_below_quorum_vote_survives_a_simulated_restart_and_an_at_quorum_vote_deletes_it() {
        let (db, dir) = open_test_db();
        let addrs_and_keys: Vec<(Address, BlsSecretKey)> = (0u8..4)
            .map(|i| {
                let ed_key = SigningKey::from_bytes(&[i + 1; 32]);
                let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
                let (sk, pk) = xc_bls::keygen_from_seed(&[i + 50; 32]).unwrap();
                db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
                (addr, sk)
            })
            .collect();
        let validators: Vec<Address> = addrs_and_keys.iter().map(|(a, _)| a.clone()).collect();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators }]).unwrap();

        let block_hash = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100).hash();

        // Below quorum (3): only 2 of 4 vote, then simulate a crash by
        // dropping the in-memory tally entirely and reconstructing it the
        // same way `spawn_finality` does on startup.
        let ep = [1u8; 32];
        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();
        for (addr, sk) in addrs_and_keys.iter().take(2) {
            let vote = PrecommitVote {
                height: 5,
                block_hash: block_hash.clone(),
                voter: addr.clone(),
                signature: xc_bls::sign(sk, &precommit_signing_bytes(5, &block_hash, &ep)),
                ep,
            };
            tally_vote(&db, &mut tallies, &mut my_votes, vote).unwrap();
        }
        drop(tallies);

        let mut reloaded: HashMap<u64, HashMap<(String, [u8; 32]), HashMap<Address, BlsSignature>>> = HashMap::new();
        for record in db.get_precommit_votes_from(0).unwrap() {
            reloaded
                .entry(record.height)
                .or_default()
                .entry((record.block_hash, record.ep))
                .or_default()
                .insert(record.voter, record.signature);
        }
        let mut reloaded_my_votes = HashMap::new();
        assert_eq!(
            reloaded.get(&5).unwrap().get(&(block_hash.clone(), ep)).unwrap().len(),
            2,
            "both pre-crash votes should have survived via persisted records"
        );

        // The 3rd vote reaches quorum and finalizes — persisted vote records
        // for that height are now superseded and must be deleted.
        let (addr, sk) = &addrs_and_keys[2];
        let vote = PrecommitVote {
            height: 5,
            block_hash: block_hash.clone(),
            voter: addr.clone(),
            signature: xc_bls::sign(sk, &precommit_signing_bytes(5, &block_hash, &ep)),
            ep,
        };
        tally_vote(&db, &mut reloaded, &mut reloaded_my_votes, vote).unwrap();
        assert!(db.get_finality_record(5).unwrap().is_some());
        assert!(
            db.get_precommit_votes_from(0).unwrap().is_empty(),
            "finalized height's persisted votes must be cleaned up"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two votes for the identical `block_hash` but a different `ep` must
    /// not aggregate into the same quorum — that's the whole point of
    /// keying `tallies` by `(block_hash, ep)` instead of `block_hash` alone.
    #[test]
    fn votes_agreeing_on_block_hash_but_disagreeing_on_ep_do_not_aggregate() {
        let (db, dir) = open_test_db();
        let addrs_and_keys: Vec<(Address, BlsSecretKey)> = (0u8..3)
            .map(|i| {
                let ed_key = SigningKey::from_bytes(&[i + 1; 32]);
                let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
                let (sk, pk) = xc_bls::keygen_from_seed(&[i + 50; 32]).unwrap();
                db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
                (addr, sk)
            })
            .collect();
        let validators: Vec<Address> = addrs_and_keys.iter().map(|(a, _)| a.clone()).collect();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators }]).unwrap();

        let block_hash = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100).hash();
        let ep_a = [1u8; 32];
        let ep_b = [2u8; 32];

        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();

        // quorum() of 3 validators is 3 — two votes on ep_a, one on ep_b:
        // neither group reaches quorum even though all three agree on
        // block_hash.
        for (i, (addr, sk)) in addrs_and_keys.iter().enumerate() {
            let ep = if i < 2 { ep_a } else { ep_b };
            let vote = PrecommitVote {
                height: 5,
                block_hash: block_hash.clone(),
                voter: addr.clone(),
                signature: xc_bls::sign(sk, &precommit_signing_bytes(5, &block_hash, &ep)),
                ep,
            };
            tally_vote(&db, &mut tallies, &mut my_votes, vote).unwrap();
        }

        assert!(db.get_finality_record(5).unwrap().is_none(), "neither ep group alone reached quorum");
        assert_eq!(tallies.get(&5).unwrap().get(&(block_hash.clone(), ep_a)).unwrap().len(), 2);
        assert_eq!(tallies.get(&5).unwrap().get(&(block_hash, ep_b)).unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn dissent_fixture(voter: Address, sk: &BlsSecretKey, height: u64, block_hash: &str) -> Dissent {
        let state_root = "0xdisputed".to_string();
        let header_commitment = [4u8; 32];
        let ep = [9u8; 32];
        let reason = DissentReason::StateRootMismatch;
        let msg = dissent_signing_bytes(height, block_hash, &state_root, &header_commitment, &ep, reason.as_str());
        Dissent {
            height,
            block_hash: block_hash.to_string(),
            state_root,
            header_commitment,
            ep,
            reason,
            voter,
            signature: xc_bls::sign(sk, &msg),
        }
    }

    #[test]
    fn valid_dissent_is_verified_tallied_and_persisted() {
        let (db, dir) = open_test_db();
        let ed_key = SigningKey::from_bytes(&[1u8; 32]);
        let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
        let (sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
        db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators: vec![addr.clone()] }])
            .unwrap();

        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let dissent = dissent_fixture(addr.clone(), &sk, 5, "0xblockhash");
        handle_dissent(&db, dissent, &dissent_tx).unwrap();

        let stored = db.get_dissent(5, &addr).unwrap().expect("dissent should be persisted");
        assert_eq!(stored.reason, "state_root_mismatch");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn duplicate_dissent_from_the_same_voter_at_the_same_height_is_dropped() {
        let (db, dir) = open_test_db();
        let ed_key = SigningKey::from_bytes(&[1u8; 32]);
        let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
        let (sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
        db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators: vec![addr.clone()] }])
            .unwrap();

        let (dissent_tx, _dissent_rx) = mpsc::channel();
        handle_dissent(&db, dissent_fixture(addr.clone(), &sk, 5, "0xblockhash"), &dissent_tx).unwrap();
        // A second, differently-shaped dissent from the same voter at the
        // same height must not overwrite the first.
        handle_dissent(&db, dissent_fixture(addr.clone(), &sk, 5, "0xotherblockhash"), &dissent_tx).unwrap();

        let stored = db.get_dissent(5, &addr).unwrap().unwrap();
        assert_eq!(stored.block_hash, "0xblockhash", "the first dissent must win, not be overwritten");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forged_dissent_signature_is_rejected() {
        let (db, dir) = open_test_db();
        let ed_key = SigningKey::from_bytes(&[1u8; 32]);
        let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
        let (_sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
        let (other_sk, _) = xc_bls::keygen_from_seed(&[51u8; 32]).unwrap();
        db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators: vec![addr.clone()] }])
            .unwrap();

        // Signed with a key that doesn't match the registered pubkey for `addr`.
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        handle_dissent(&db, dissent_fixture(addr.clone(), &other_sk, 5, "0xblockhash"), &dissent_tx).unwrap();

        assert!(db.get_dissent(5, &addr).unwrap().is_none(), "a forged dissent signature must not be persisted");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `TALLY_RETENTION_HEIGHTS` prunes unfinalized precommit tallies because
    /// a vote that never reached quorum is noise — but a dissent is a signed
    /// claim a fault occurred, and heights that never finalize are exactly
    /// where dissents live. This drives `spawn_finality`'s real event loop
    /// (not a standalone copy of the pruning logic) to prove the dissent
    /// survives long after the vote-retention window for its height closes.
    #[test]
    fn a_dissent_survives_the_tip_advancing_past_its_vote_retention_window() {
        let (db, dir) = open_test_db();
        let ed_key = SigningKey::from_bytes(&[1u8; 32]);
        let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
        let (sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
        db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }])
            .unwrap();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators: vec![addr.clone()] }])
            .unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (vote_tx, _vote_rx) = mpsc::channel();
        let (round_timeout_tx, _round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        // No bls_identity: this test only needs the loop's pruning step to
        // run on every event, not for this node to vote.
        let handle = spawn_finality::<()>(db.clone(), None, event_rx, vote_tx, round_timeout_tx, dissent_tx);

        let dissent_height = 5;
        event_tx
            .send(FinalityEvent::DissentObserved(dissent_fixture(addr.clone(), &sk, dissent_height, "0xblockhash")))
            .unwrap();

        // Push the tip well past `dissent_height + TALLY_RETENTION_HEIGHTS` —
        // this is what drives the pruning cutoff in the real loop.
        for height in 1..=(dissent_height + TALLY_RETENTION_HEIGHTS + 10) {
            event_tx
                .send(FinalityEvent::BlockObserved(signed_block(&ed_key, height, 100 + height)))
                .unwrap();
        }
        drop(event_tx);
        handle.join().expect("finality worker should stop cleanly");

        assert!(
            db.get_dissent(dissent_height, &addr).unwrap().is_some(),
            "a dissent must not be pruned once its height falls outside the vote retention window"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_finality_signs_and_emits_a_vote_for_observed_blocks() {
        let (db, dir) = open_test_db();
        let (sk, _pk) = xc_bls::keygen_from_seed(&[3u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (vote_tx, vote_rx) = mpsc::channel();
        let (round_timeout_tx, _round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let handle = spawn_finality::<()>(
            db,
            Some((addr.clone(), sk)),
            event_rx,
            vote_tx,
            round_timeout_tx,
            dissent_tx,
        );

        let block = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100);
        let expected_hash = block.hash();
        event_tx.send(FinalityEvent::BlockObserved(block)).unwrap();
        drop(event_tx);

        let vote = vote_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected a precommit vote");
        assert_eq!(vote.height, 5);
        assert_eq!(vote.voter, addr);
        assert_eq!(vote.block_hash, expected_hash);
        handle.join().expect("finality worker should stop cleanly");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_finality_tallies_its_local_precommit_before_gossip() {
        let (db, dir) = open_test_db();
        let (sk, pk) = xc_bls::keygen_from_seed(&[3u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();
        let peer = Address::from_pubkey_bytes(&[5u8; 32]).unwrap();
        db.write_batches(&[
            &xc_storage::BlsKeyRegistration {
                address: addr.clone(),
                pubkey: pk,
                effective_height: 0,
            },
            &xc_storage::ValidatorSetSnapshot {
                effective_height: 0,
                validators: vec![addr.clone(), peer],
            },
        ])
        .unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (vote_tx, vote_rx) = mpsc::channel();
        let (round_timeout_tx, _round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let handle = spawn_finality::<()>(
            db.clone(),
            Some((addr.clone(), sk)),
            event_rx,
            vote_tx,
            round_timeout_tx,
            dissent_tx,
        );

        event_tx
            .send(FinalityEvent::BlockObserved(signed_block(
                &SigningKey::from_bytes(&[9u8; 32]),
                5,
                100,
            )))
            .unwrap();
        drop(event_tx);

        let vote = vote_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected a precommit vote");
        let persisted = db.get_precommit_votes_from(0).unwrap();
        assert_eq!(
            persisted.len(),
            1,
            "the local vote must enter the tally without gossip loopback"
        );
        assert_eq!(persisted[0].voter, addr);
        assert_eq!(persisted[0].height, vote.height);
        handle.join().expect("finality worker should stop cleanly");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A vote is only gossiped once, on observation. If that single message
    /// is lost, the height must not be stuck forever — the node should keep
    /// re-sending its own not-yet-finalized vote.
    #[test]
    fn spawn_finality_rebroadcasts_its_own_unfinalized_vote() {
        let (db, dir) = open_test_db();
        let (sk, _pk) = xc_bls::keygen_from_seed(&[5u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[6u8; 32]).unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (vote_tx, vote_rx) = mpsc::channel();
        let (round_timeout_tx, _round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let handle = spawn_finality::<()>(
            db,
            Some((addr.clone(), sk)),
            event_rx,
            vote_tx,
            round_timeout_tx,
            dissent_tx,
        );

        let block = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100);
        event_tx.send(FinalityEvent::BlockObserved(block)).unwrap();

        let first = vote_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected the initial vote");
        assert_eq!(first.height, 5);

        // No further events arrive, but the interval (shortened for tests)
        // should fire a resend of the same vote without any new input.
        let resent = vote_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected a rebroadcast");
        assert_eq!(resent.height, first.height);
        assert_eq!(resent.signature, first.signature);

        drop(event_tx);
        handle.join().expect("finality worker should stop cleanly");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `tallies` used to be pruned only when a height finalized, so a chain
    /// that never reaches quorum grew the map forever. This drives the same
    /// shape — votes that never reach quorum, across far more heights than the
    /// retention window — and requires the map to stay bounded.
    #[test]
    fn unfinalized_tallies_do_not_grow_without_bound() {
        let mut tallies: HashMap<u64, HashMap<(String, [u8; 32]), HashMap<Address, BlsSignature>>> =
            HashMap::new();

        // Stand in for the loop's pruning step, which is what the retention
        // constant actually drives.
        let mut highest_seen = 0u64;
        for height in 0..(TALLY_RETENTION_HEIGHTS * 4) {
            highest_seen = highest_seen.max(height);
            let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
            tallies.retain(|h, _| *h >= cutoff);
            // A vote arrives for this height and never reaches quorum.
            tallies.entry(height).or_default().entry(("0xdeadbeef".into(), [0u8; 32])).or_default();
        }

        assert!(
            tallies.len() as u64 <= TALLY_RETENTION_HEIGHTS + 1,
            "tallies grew to {} entries over {} heights — retention is not bounding it",
            tallies.len(),
            TALLY_RETENTION_HEIGHTS * 4,
        );
        // And it keeps the recent ones, rather than bounding by dropping
        // everything.
        assert!(
            tallies.contains_key(&(TALLY_RETENTION_HEIGHTS * 4 - 1)),
            "the most recent height must survive pruning",
        );
    }

    /// Quorum moved to `core/primitives` so `core/rpc` could report it without
    /// depending on `arxd/`. This pins the values the finality path relies on,
    /// so a change there cannot silently alter what counts as final.
    #[test]
    fn quorum_matches_the_shared_consensus_rule() {
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(2), 2);
        assert_eq!(quorum(3), 3);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(7), 5);
    }

    fn round_timeout_validators(db: &ArxiumDb, count: u8) -> Vec<(Address, BlsSecretKey)> {
        let addrs_and_keys: Vec<(Address, BlsSecretKey)> = (0u8..count)
            .map(|i| {
                let ed_key = SigningKey::from_bytes(&[i + 1; 32]);
                let addr = Address::from_pubkey_bytes(ed_key.verifying_key().as_bytes()).unwrap();
                let (sk, pk) = xc_bls::keygen_from_seed(&[i + 50; 32]).unwrap();
                db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk, effective_height: 0 }]).unwrap();
                (addr, sk)
            })
            .collect();
        let validators: Vec<Address> = addrs_and_keys.iter().map(|(a, _)| a.clone()).collect();
        db.write_batches(&[&xc_storage::ValidatorSetSnapshot { effective_height: 0, validators }]).unwrap();
        addrs_and_keys
    }

    /// Writes a stub parent block at `height` so tests can sign/verify
    /// round-timeout votes against it — `round_timeout_signing_bytes` now
    /// binds the parent hash, so a round-timeout vote needs an actual parent
    /// block in the db, not just a bare height/round pair.
    fn parent_block_for(db: &ArxiumDb, height: u64) -> Block<()> {
        let mut block: Block<()> = Block::genesis(1_000_000 + height);
        block.height = height;
        db.write_batches(&[&block]).unwrap();
        block
    }

    fn round_timeout_vote(
        addr: &Address,
        sk: &BlsSecretKey,
        height: u64,
        round: u32,
        parent_hash: &str,
    ) -> RoundTimeoutVote {
        RoundTimeoutVote {
            height,
            round,
            voter: addr.clone(),
            signature: xc_bls::sign(sk, &round_timeout_signing_bytes(height, round, parent_hash)),
        }
    }

    /// Mirrors `no_finality_record_below_quorum_then_one_appears_at_quorum`:
    /// no `RoundCertificate` exists below quorum, and one appears — signed
    /// by exactly the voters who tallied — the moment quorum is reached.
    #[test]
    fn no_round_certificate_below_quorum_then_one_appears_at_quorum() {
        let (db, dir) = open_test_db();
        let addrs_and_keys = round_timeout_validators(&db, 4);
        let parent = parent_block_for(&db, 4);
        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();

        for (addr, sk) in &addrs_and_keys[..2] {
            tally_round_timeout::<()>(
                &db,
                &mut tallies,
                &mut my_votes,
                round_timeout_vote(addr, sk, 5, 0, &parent.hash()),
            )
            .unwrap();
        }
        assert!(db.get_round_certificate(5, 0).unwrap().is_none(), "below quorum (2 of 4) must not certify");

        let (addr, sk) = &addrs_and_keys[2];
        tally_round_timeout::<()>(
            &db,
            &mut tallies,
            &mut my_votes,
            round_timeout_vote(addr, sk, 5, 0, &parent.hash()),
        )
        .unwrap();

        let record = db.get_round_certificate(5, 0).unwrap().expect("expected a certificate at quorum");
        assert_eq!(record.signers.len(), 3);
        assert_eq!(db.current_round(5).unwrap(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Mirrors `votes_agreeing_on_block_hash_but_disagreeing_on_ep_do_not_aggregate`:
    /// votes for different rounds of the same height must tally separately —
    /// a quorum on round 0 must not also certify round 1.
    #[test]
    fn votes_for_different_rounds_do_not_cross_aggregate() {
        let (db, dir) = open_test_db();
        let addrs_and_keys = round_timeout_validators(&db, 3);
        let parent = parent_block_for(&db, 4);
        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();

        let (addr0, sk0) = &addrs_and_keys[0];
        let (addr1, sk1) = &addrs_and_keys[1];
        tally_round_timeout::<()>(
            &db,
            &mut tallies,
            &mut my_votes,
            round_timeout_vote(addr0, sk0, 5, 0, &parent.hash()),
        )
        .unwrap();
        tally_round_timeout::<()>(
            &db,
            &mut tallies,
            &mut my_votes,
            round_timeout_vote(addr1, sk1, 5, 1, &parent.hash()),
        )
        .unwrap();

        assert!(db.get_round_certificate(5, 0).unwrap().is_none());
        assert!(db.get_round_certificate(5, 1).unwrap().is_none());
        assert_eq!(db.current_round(5).unwrap(), 0, "neither round has reached quorum yet");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Once a round is certified, a late vote for that same round is a
    /// no-op — mirrors `tally_vote`'s "already finalized" short-circuit.
    #[test]
    fn a_vote_for_an_already_certified_round_is_a_no_op() {
        let (db, dir) = open_test_db();
        let addrs_and_keys = round_timeout_validators(&db, 3);
        let parent = parent_block_for(&db, 4);
        let mut tallies = HashMap::new();
        let mut my_votes = HashMap::new();

        for (addr, sk) in &addrs_and_keys {
            tally_round_timeout::<()>(
                &db,
                &mut tallies,
                &mut my_votes,
                round_timeout_vote(addr, sk, 5, 0, &parent.hash()),
            )
            .unwrap();
        }
        assert_eq!(db.current_round(5).unwrap(), 1);

        // A 4th, unregistered voter's vote arrives after certification.
        let late_key = SigningKey::from_bytes(&[9u8; 32]);
        let late_addr = Address::from_pubkey_bytes(late_key.verifying_key().as_bytes()).unwrap();
        let (late_sk, _pk) = xc_bls::keygen_from_seed(&[99u8; 32]).unwrap();
        tally_round_timeout::<()>(
            &db,
            &mut tallies,
            &mut my_votes,
            round_timeout_vote(&late_addr, &late_sk, 5, 0, &parent.hash()),
        )
        .unwrap();

        // Still exactly the original 3 signers, no crash, no round change.
        let record = db.get_round_certificate(5, 0).unwrap().unwrap();
        assert_eq!(record.signers.len(), 3);
        assert_eq!(db.current_round(5).unwrap(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `spawn_finality` signs and emits a round-timeout vote once the chain
    /// tip has been stuck (no `BlockObserved`) for `ROUND_TIMEOUT`.
    #[test]
    fn spawn_finality_signs_a_round_timeout_vote_once_the_tip_stalls() {
        let (db, dir) = open_test_db();
        parent_block_for(&db, 0);
        let (sk, _pk) = xc_bls::keygen_from_seed(&[3u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (_vote_tx, _vote_rx) = mpsc::channel();
        let (round_timeout_tx, round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let handle = spawn_finality::<()>(
            db,
            Some((addr.clone(), sk)),
            event_rx,
            _vote_tx,
            round_timeout_tx,
            dissent_tx,
        );

        let vote = round_timeout_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected a round-timeout vote");
        assert_eq!(vote.height, 1); // last_progress starts at height 0, so next_height is 1
        assert_eq!(vote.round, 0);
        assert_eq!(vote.voter, addr);
        drop(event_tx);
        handle.join().expect("finality worker should stop cleanly");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_finality_tallies_its_local_round_timeout_before_gossip() {
        let (db, dir) = open_test_db();
        parent_block_for(&db, 0);
        let (sk, pk) = xc_bls::keygen_from_seed(&[3u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();
        let peer = Address::from_pubkey_bytes(&[5u8; 32]).unwrap();
        db.write_batches(&[
            &xc_storage::BlsKeyRegistration {
                address: addr.clone(),
                pubkey: pk,
                effective_height: 0,
            },
            &xc_storage::ValidatorSetSnapshot {
                effective_height: 0,
                validators: vec![addr.clone(), peer],
            },
        ])
        .unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (_vote_tx, _vote_rx) = mpsc::channel();
        let (round_timeout_tx, round_timeout_rx) = mpsc::channel();
        let (dissent_tx, _dissent_rx) = mpsc::channel();
        let handle = spawn_finality::<()>(
            db.clone(),
            Some((addr.clone(), sk)),
            event_rx,
            _vote_tx,
            round_timeout_tx,
            dissent_tx,
        );

        let vote = round_timeout_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("expected a round-timeout vote");
        let persisted = db.get_round_timeout_votes_from(0).unwrap();
        assert_eq!(
            persisted.len(),
            1,
            "the local timeout vote must enter the tally without gossip loopback"
        );
        assert_eq!(persisted[0].voter, addr);
        assert_eq!(persisted[0].height, vote.height);
        assert_eq!(persisted[0].round, vote.round);
        drop(event_tx);
        handle.join().expect("finality worker should stop cleanly");

        std::fs::remove_dir_all(&dir).ok();
    }
}
