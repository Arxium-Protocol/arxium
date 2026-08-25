// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{info, warn};
use xc_bls::{BlsPublicKey, BlsSecretKey, BlsSignature};
use xc_primitives::{Address, Block, quorum};
use xc_storage::{ArxiumDb, FinalityRecord};

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

/// One validator's BLS-signed vote that it also attests to `block_hash` at
/// `height` — gossiped over `arxd/network`'s precommit topic and fed back
/// into `spawn_finality` on every node, including the signer's own.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct PrecommitVote {
    pub height: u64,
    pub block_hash: String,
    pub voter: Address,
    pub signature: BlsSignature,
}

/// Fed to `spawn_finality`: either a block this node just accepted/produced
/// (triggers signing a precommit, if this node has a BLS identity), or a
/// precommit vote received from a peer (tallied toward quorum).
pub enum FinalityEvent<P> {
    BlockObserved(Block<P>),
    VoteObserved(PrecommitVote),
}

/// Runs on its own thread. `bls_identity` is `Some((address, secret_key))`
/// on a node that holds a registered BLS key — it still tallies and
/// finalizes without one, it just can't contribute a vote. `vote_tx` is
/// where freshly-signed precommits go out to be gossiped; `events` carries
/// both locally-observed blocks and incoming peer votes.
pub fn spawn_finality<P>(
    db: ArxiumDb,
    bls_identity: Option<(Address, BlsSecretKey)>,
    events: Receiver<FinalityEvent<P>>,
    vote_tx: Sender<PrecommitVote>,
) where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    thread::spawn(move || {
        // height -> (block_hash -> (voter -> signature)); a height can only
        // ever have one canonical hash in practice, but keyed this way a
        // stray vote for a competing hash can't corrupt the real tally.
        let mut tallies: HashMap<u64, HashMap<String, HashMap<Address, BlsSignature>>> = HashMap::new();

        // Highest height seen from either event kind, used as the pruning
        // watermark below.
        let mut highest_seen: u64 = 0;

        for event in events {
            highest_seen = highest_seen.max(match &event {
                FinalityEvent::BlockObserved(block) => block.height,
                FinalityEvent::VoteObserved(vote) => vote.height,
            });
            // Bounded on every event rather than only on finalization, which
            // is the case that may never come.
            let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
            tallies.retain(|height, _| *height >= cutoff);

            match event {
                FinalityEvent::BlockObserved(block) => {
                    let Some((address, secret_key)) = &bls_identity else { continue };
                    let hash = block.hash();
                    let signature = xc_bls::sign(secret_key, hash.as_bytes());
                    let vote = PrecommitVote { height: block.height, block_hash: hash, voter: address.clone(), signature };
                    if vote_tx.send(vote).is_err() {
                        warn!("finality: vote channel closed, stopping");
                        return;
                    }
                }
                FinalityEvent::VoteObserved(vote) => {
                    if let Err(err) = tally_vote(&db, &mut tallies, vote) {
                        warn!("finality: failed to process precommit vote: {err}");
                    }
                }
            }
        }
    });
}

fn tally_vote(
    db: &ArxiumDb,
    tallies: &mut HashMap<u64, HashMap<String, HashMap<Address, BlsSignature>>>,
    vote: PrecommitVote,
) -> Result<(), xc_storage::StorageError> {
    if db.get_finality_record(vote.height)?.is_some() {
        return Ok(()); // already finalized, nothing left to tally
    }

    let Some(pubkey) = db.get_bls_pubkey(&vote.voter)? else {
        warn!("finality: vote from {} with no registered BLS key, dropping", vote.voter);
        return Ok(());
    };
    if xc_bls::verify(vote.block_hash.as_bytes(), &pubkey, &vote.signature).is_err() {
        warn!("finality: dropping vote from {} with an invalid signature", vote.voter);
        return Ok(());
    }

    let validators = db.get_validator_set_at(vote.height)?;
    if !validators.contains(&vote.voter) {
        warn!("finality: dropping vote from {}, not a validator at height {}", vote.voter, vote.height);
        return Ok(());
    }

    let signers = tallies
        .entry(vote.height)
        .or_default()
        .entry(vote.block_hash.clone())
        .or_default();
    signers.insert(vote.voter, vote.signature);

    if signers.len() < quorum(validators.len()) {
        return Ok(());
    }

    let pubkeys: Vec<BlsPublicKey> = signers
        .keys()
        .filter_map(|addr| db.get_bls_pubkey(addr).ok().flatten())
        .collect();
    let sigs: Vec<BlsSignature> = signers.values().cloned().collect();
    let Ok(aggregate_signature) = xc_bls::aggregate(&sigs) else {
        warn!("finality: failed to aggregate signatures for height {}", vote.height);
        return Ok(());
    };
    if xc_bls::verify_aggregate(vote.block_hash.as_bytes(), &pubkeys, &aggregate_signature).is_err() {
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
    tallies.remove(&vote.height);
    info!("finality: block {} finalized with {} signers", vote.height, record.signers.len());
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
                db.write_batches(&[&xc_storage::BlsKeyRegistration { address: addr.clone(), pubkey: pk }]).unwrap();
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

        // 3 of 4 validators is quorum() == 3; first two votes shouldn't finalize.
        for (addr, sk) in addrs_and_keys.iter().take(2) {
            let vote = PrecommitVote {
                height: 5,
                block_hash: block_hash.clone(),
                voter: addr.clone(),
                signature: xc_bls::sign(sk, block_hash.as_bytes()),
            };
            tally_vote(&db, &mut tallies, vote).unwrap();
            assert!(db.get_finality_record(5).unwrap().is_none());
        }

        let (addr, sk) = &addrs_and_keys[2];
        let vote = PrecommitVote {
            height: 5,
            block_hash: block_hash.clone(),
            voter: addr.clone(),
            signature: xc_bls::sign(sk, block_hash.as_bytes()),
        };
        tally_vote(&db, &mut tallies, vote).unwrap();

        let record = db.get_finality_record(5).unwrap().expect("expected finality record at quorum");
        assert_eq!(record.signers.len(), 3);
        assert_eq!(record.block_hash, block_hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_finality_signs_and_emits_a_vote_for_observed_blocks() {
        let (db, dir) = open_test_db();
        let (sk, _pk) = xc_bls::keygen_from_seed(&[3u8; 32]).unwrap();
        let addr = Address::from_pubkey_bytes(&[4u8; 32]).unwrap();

        let (event_tx, event_rx) = mpsc::channel();
        let (vote_tx, vote_rx) = mpsc::channel();
        spawn_finality::<()>(db, Some((addr.clone(), sk)), event_rx, vote_tx);

        let block = signed_block(&SigningKey::from_bytes(&[9u8; 32]), 5, 100);
        let expected_hash = block.hash();
        event_tx.send(FinalityEvent::BlockObserved(block)).unwrap();
        drop(event_tx);

        let vote = vote_rx.recv_timeout(std::time::Duration::from_secs(2)).expect("expected a precommit vote");
        assert_eq!(vote.height, 5);
        assert_eq!(vote.voter, addr);
        assert_eq!(vote.block_hash, expected_hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `tallies` used to be pruned only when a height finalized, so a chain
    /// that never reaches quorum grew the map forever. This drives the same
    /// shape — votes that never reach quorum, across far more heights than the
    /// retention window — and requires the map to stay bounded.
    #[test]
    fn unfinalized_tallies_do_not_grow_without_bound() {
        let mut tallies: HashMap<u64, HashMap<String, HashMap<Address, BlsSignature>>> =
            HashMap::new();

        // Stand in for the loop's pruning step, which is what the retention
        // constant actually drives.
        let mut highest_seen = 0u64;
        for height in 0..(TALLY_RETENTION_HEIGHTS * 4) {
            highest_seen = highest_seen.max(height);
            let cutoff = highest_seen.saturating_sub(TALLY_RETENTION_HEIGHTS);
            tallies.retain(|h, _| *h >= cutoff);
            // A vote arrives for this height and never reaches quorum.
            tallies.entry(height).or_default().entry("0xdeadbeef".into()).or_default();
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
}
