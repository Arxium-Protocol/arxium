// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Snapshot sync — both ends of `SyncRequest::SnapshotManifest`/
//! `SnapshotChunk`, kept out of the swarm loop as plain functions so the
//! trust checks are testable without a swarm.
//!
//! Server: `manifest`/`chunk` read `ArxiumDb::state_at` (see
//! `xc_storage::snapshot` for how a past height is reconstructed) and cache
//! the last height served, since a client fetches every chunk of one height
//! back to back.
//!
//! Client: [`SnapshotSync`] is the state machine behind
//! `--snapshot-trust-height`/`--snapshot-trust-hash`. It runs only on a node
//! still at genesis, and everything it accepts is checked against the
//! operator's anchor before a byte is written: the manifest's block must hash
//! to the trusted hash; every chunk must match its manifest checksum; the
//! finality certificate must be a quorum of the validator set *the snapshot
//! carries*, signed under the BLS keys it carries; and `import_snapshot`
//! recomputes the state root and refuses anything that does not hash to the
//! trusted block's `state_root`. Cosmos's trust-height/trust-hash model.

use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use xc_circuit::{BlsKeyKey, ChainParamsKey, GenesisHashKey, KeySpec, ValidatorSetKey};
use xc_primitives::{Block, Hash32, quorum_reached, validator_set_effective_height};
use xc_storage::{ArxiumDb, FinalityRecord, StorageError, snapshot_chunks};
use xc_wire::{SnapshotEntry, SnapshotManifest, SyncRequest};

use crate::gossip::Payload;

/// The operator's trust anchor: a finalized block's height and hash, read
/// off an explorer or another node they trust. Nothing in the protocol
/// vouches for it — that is the point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotTrust {
    pub height: u64,
    pub block_hash: Hash32,
}

// ---------------------------------------------------------------- server --

/// Last height served, with its entries. One entry: a client walks one
/// snapshot's chunks in order, and a second client at another height simply
/// replaces it. ponytail: refetched from `state_at` on a miss, which is
/// exact (same undo records) just slower.
static SERVED: Mutex<Option<(u64, Instant, std::sync::Arc<Vec<SnapshotEntry>>)>> = Mutex::new(None);
const SERVED_TTL: Duration = Duration::from_secs(10 * 60);

fn entries_at(db: &ArxiumDb, height: u64) -> Option<std::sync::Arc<Vec<SnapshotEntry>>> {
    let mut served = SERVED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((h, at, entries)) = served.as_ref()
        && *h == height
        && at.elapsed() < SERVED_TTL
    {
        return Some(entries.clone());
    }
    let entries = match db.state_at(height) {
        Ok(Some(entries)) => std::sync::Arc::new(entries),
        Ok(None) => return None,
        Err(err) => {
            warn!("snapshot: failed to reconstruct state at {height}: {err}");
            return None;
        }
    };
    *served = Some((height, Instant::now(), entries.clone()));
    Some(entries)
}

pub(crate) fn chunk_hash(entries: &[SnapshotEntry]) -> [u8; 32] {
    let bytes = bincode::serde::encode_to_vec(entries, xc_primitives::wire_config()).unwrap_or_default();
    Sha256::digest(bytes).into()
}

/// Only a *certified* height is served: a snapshot of a provisional tip is
/// a snapshot of a guess.
pub(crate) fn manifest<P: Payload>(db: &ArxiumDb, height: u64) -> Option<SnapshotManifest> {
    let certificate = db.get_finality_record(height).ok().flatten()?;
    let block: Block<P> = db.get_block(height).ok().flatten()?;
    let entries = entries_at(db, height)?;
    let ranges = snapshot_chunks(&entries);
    Some(SnapshotManifest {
        height,
        block_hash: block.hash(),
        state_root: block.state_root.clone(),
        entries: entries.len() as u64,
        chunks: ranges.len() as u32,
        chunk_hashes: ranges.iter().map(|r| chunk_hash(&entries[r.clone()])).collect(),
        block: bincode::serde::encode_to_vec(&block, xc_primitives::wire_config()).ok()?,
        certificate: bincode::serde::encode_to_vec(&certificate, xc_primitives::wire_config()).ok()?,
    })
}

pub(crate) fn chunk(db: &ArxiumDb, height: u64, index: u32) -> Option<Vec<SnapshotEntry>> {
    let entries = entries_at(db, height)?;
    let range = snapshot_chunks(&entries).into_iter().nth(index as usize)?;
    Some(entries[range].to_vec())
}

// ---------------------------------------------------------------- client --

/// Where a joining node is in its snapshot download. Created at startup
/// from the operator's anchor; dropped (into `Done`/`Failed`) once the
/// state is imported or the anchor proves unusable.
pub(crate) struct SnapshotSync<P> {
    trust: SnapshotTrust,
    manifest: Option<SnapshotManifest>,
    block: Option<Block<P>>,
    certificate: Option<FinalityRecord>,
    chunks: Vec<Option<Vec<SnapshotEntry>>>,
    /// The peer whose manifest we are following; chunks from anyone else
    /// are ignored so two peers cannot interleave different states.
    peer: Option<libp2p::PeerId>,
    /// Peers that could not (or would not) serve the anchor. ponytail: never
    /// cleared — if every peer fails, the operator picks a newer anchor.
    tried: std::collections::HashSet<libp2p::PeerId>,
}

pub(crate) enum Step {
    /// Send this to the peer next.
    Request(SyncRequest),
    /// Snapshot imported; the normal `Blocks { from }` sync takes over.
    Done,
    /// This peer cannot help (or lied); try another peer's manifest.
    Retry,
    /// Nothing to do for this message.
    Idle,
}

impl<P: Payload> SnapshotSync<P> {
    pub(crate) fn new(trust: SnapshotTrust) -> Self {
        Self {
            trust,
            manifest: None,
            block: None,
            certificate: None,
            chunks: Vec::new(),
            peer: None,
            tried: std::collections::HashSet::new(),
        }
    }

    pub(crate) fn height(&self) -> u64 {
        self.trust.height
    }

    /// A peer's `Status` tip says whether it might serve the anchor height;
    /// whether it is certified there is the manifest's answer.
    pub(crate) fn on_peer_tip(&mut self, peer: libp2p::PeerId, tip_height: u64) -> Step {
        if self.peer.is_some() || tip_height < self.trust.height || self.tried.contains(&peer) {
            return Step::Idle;
        }
        self.tried.insert(peer);
        self.peer = Some(peer);
        info!("snapshot sync: asking {peer} for state at trusted height {}", self.trust.height);
        Step::Request(SyncRequest::SnapshotManifest { height: self.trust.height })
    }

    pub(crate) fn on_manifest(&mut self, peer: libp2p::PeerId, manifest: Option<SnapshotManifest>) -> Step {
        if self.peer != Some(peer) {
            return Step::Idle;
        }
        let Some(manifest) = manifest else {
            warn!("snapshot sync: {peer} cannot serve height {}", self.trust.height);
            return self.retry();
        };
        if manifest.height != self.trust.height || manifest.block_hash != self.trust.block_hash {
            warn!(
                "snapshot sync: {peer} offered block {} at {}, trust anchor is {} — refusing",
                manifest.block_hash, manifest.height, self.trust.block_hash
            );
            return self.retry();
        }
        let (Ok(block), Ok(certificate)) = (
            xc_primitives::decode_wire_canonical::<Block<P>>(&manifest.block),
            xc_primitives::decode_wire_canonical::<FinalityRecord>(&manifest.certificate),
        ) else {
            warn!("snapshot sync: {peer} sent an undecodable block or certificate");
            return self.retry();
        };
        // The anchor is a *block hash*, so the block bytes are what the
        // operator trusts; everything else in the manifest is checked
        // against them.
        if block.hash() != self.trust.block_hash || block.state_root != manifest.state_root {
            warn!("snapshot sync: manifest from {peer} does not match its own block");
            return self.retry();
        }
        if manifest.chunk_hashes.len() != manifest.chunks as usize || manifest.chunks == 0 {
            warn!("snapshot sync: malformed manifest from {peer}");
            return self.retry();
        }
        info!(
            "snapshot sync: {peer} offers {} entries in {} chunk(s) at height {}",
            manifest.entries, manifest.chunks, manifest.height
        );
        self.chunks = vec![None; manifest.chunks as usize];
        self.manifest = Some(manifest);
        self.block = Some(block);
        self.certificate = Some(certificate);
        Step::Request(SyncRequest::SnapshotChunk { height: self.trust.height, index: 0 })
    }

    pub(crate) fn on_chunk(
        &mut self,
        peer: libp2p::PeerId,
        db: &ArxiumDb,
        height: u64,
        index: u32,
        entries: Option<Vec<SnapshotEntry>>,
    ) -> Step {
        if self.peer != Some(peer) || height != self.trust.height {
            return Step::Idle;
        }
        let Some(manifest) = &self.manifest else {
            return Step::Idle;
        };
        let Some(entries) = entries else {
            warn!("snapshot sync: {peer} stopped serving chunk {index} of height {height}");
            return self.retry();
        };
        let Some(expected) = manifest.chunk_hashes.get(index as usize) else {
            return Step::Idle;
        };
        if chunk_hash(&entries) != *expected {
            warn!("snapshot sync: chunk {index} from {peer} fails its checksum");
            return self.retry();
        }
        self.chunks[index as usize] = Some(entries);
        if let Some(next) = self.chunks.iter().position(Option::is_none) {
            return Step::Request(SyncRequest::SnapshotChunk { height, index: next as u32 });
        }

        let entries: Vec<SnapshotEntry> = self.chunks.drain(..).flatten().flatten().collect();
        let (Some(block), Some(certificate)) = (self.block.take(), self.certificate.take()) else {
            return Step::Idle;
        };
        match verify_certificate_against(&entries, &certificate, &block) {
            Ok(()) => {}
            Err(reason) => {
                warn!("snapshot sync: certificate from {peer} does not verify against the snapshot's own validator set: {reason}");
                return self.retry();
            }
        }
        match db.import_snapshot(&entries, &block, &certificate) {
            Ok(()) => {
                info!(
                    "snapshot sync: imported {} entries; tip is now {} ({})",
                    entries.len(),
                    block.height,
                    block.hash()
                );
                Step::Done
            }
            Err(StorageError::SnapshotRejected(reason)) => {
                warn!("snapshot sync: rejected snapshot from {peer}: {reason}");
                self.retry()
            }
            Err(err) => {
                warn!("snapshot sync: import failed: {err}");
                Step::Retry
            }
        }
    }

    fn retry(&mut self) -> Step {
        self.peer = None;
        self.manifest = None;
        self.block = None;
        self.certificate = None;
        self.chunks.clear();
        Step::Retry
    }
}

fn entry<K: KeySpec>(entries: &[SnapshotEntry], key: &K) -> Option<K::Value> {
    let raw = key.encode();
    let (_, _, value) = entries.iter().find(|(_, k, _)| *k == raw)?;
    xc_primitives::decode_wire_canonical(value).ok()
}

/// `arxd_finality::verify_finality_record`, but against a downloaded state
/// instead of this node's database — the set in force at the snapshot
/// height, each signer's current BLS key, and the chain's genesis hash all
/// come from `entries`. Circular on its own (a fabricated state could carry
/// a fabricated set), which is exactly why the block hash is anchored by
/// the operator first; this check catches a peer serving real state with a
/// forged or misplaced certificate.
fn verify_certificate_against<P: Payload>(
    entries: &[SnapshotEntry],
    record: &FinalityRecord,
    block: &Block<P>,
) -> Result<(), String> {
    if record.height != block.height || record.block_hash != block.hash() {
        return Err("certificate names another block".into());
    }
    let epoch_length = entry(entries, &ChainParamsKey).unwrap_or_default().epoch_length;
    let effective = validator_set_effective_height(block.height, epoch_length);
    let validators = entry(entries, &ValidatorSetKey(effective)).ok_or("snapshot carries no validator set")?;
    let unique: std::collections::BTreeSet<_> = record.signers.iter().collect();
    if unique.len() != record.signers.len() || !unique.iter().all(|s| validators.contains_key(s)) {
        return Err("signers are not distinct members of the set".into());
    }
    if !quorum_reached(&validators, record.signers.iter()) {
        return Err("below quorum".into());
    }
    let mut pubkeys = Vec::with_capacity(record.signers.len());
    for signer in &record.signers {
        pubkeys.push(entry(entries, &BlsKeyKey(signer)).ok_or_else(|| format!("no BLS key for {signer}"))?);
    }
    let genesis: String = entry(entries, &GenesisHashKey).ok_or("snapshot carries no genesis hash")?;
    let genesis: [u8; 32] = hex::decode(genesis.strip_prefix("0x").unwrap_or(&genesis))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("malformed genesis hash")?;
    let msg = arxd_finality::precommit_signing_bytes(&genesis, record.height, &record.block_hash.to_string(), &record.ep);
    xc_bls::verify_aggregate(&msg, &pubkeys, &record.aggregate_signature).map_err(|e| format!("aggregate: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, Address};
    use xc_storage::{AccountUpdates, BlsKeyRegistration, ChainParamsRow, GenesisHash, ValidatorSetSnapshot};

    fn temp_db(tag: &str) -> ArxiumDb {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-snapshot-sync-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        ArxiumDb::open(&dir).unwrap()
    }

    const GENESIS: [u8; 32] = [0x42; 32];

    fn commit(db: &ArxiumDb, height: u64, balance: u128) -> Block<()> {
        let updates = AccountUpdates(BTreeMap::from([(
            Address::from_pubkey_bytes(&[1u8; 32]).unwrap(),
            AccountEntry { balance, ..Default::default() },
        )]));
        let state_root = db.compute_state_root(&[&updates]).unwrap();
        let parent_hash =
            db.get_block::<()>(height.saturating_sub(1)).unwrap().map(|b| b.hash().to_string()).unwrap_or_default();
        let block = Block::<()> {
            height,
            parent_hash,
            timestamp: height,
            actions: Vec::new(),
            tx_root: [0u8; 32],
            proposer: None,
            signature: None,
            state_root,
            round: 0,
            round_certificate: None,
        };
        db.write_block_batches(height, &[&updates, &block], true).unwrap();
        block
    }

    /// A one-validator chain whose validator really signs the certificate,
    /// so the client's quorum/aggregate check has something to verify.
    fn source_chain() -> (ArxiumDb, Block<()>, FinalityRecord) {
        let db = temp_db("source");
        let validator = Address::from_pubkey_bytes(&[7u8; 32]).unwrap();
        let (sk, pk) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        db.write_batch(&GenesisHash(format!("0x{}", hex::encode(GENESIS)))).unwrap();
        db.write_batch(&ChainParamsRow(Default::default())).unwrap();
        db.write_batch(&ValidatorSetSnapshot::equal_power(0, &[validator.clone()])).unwrap();
        db.write_batch(&BlsKeyRegistration { address: validator.clone(), pubkey: pk, effective_height: 0, previous_pubkey: None })
            .unwrap();
        let mut block = commit(&db, 0, 0);
        for height in 1..=3 {
            block = commit(&db, height, height as u128 * 10);
        }
        let ep = [0u8; 32];
        let msg = arxd_finality::precommit_signing_bytes(&GENESIS, 3, &block.hash().to_string(), &ep);
        let record = FinalityRecord {
            height: 3,
            block_hash: block.hash(),
            signers: vec![validator],
            aggregate_signature: xc_bls::sign(&sk, &msg),
            ep,
        };
        db.write_batch(&record).unwrap();
        (db, block, record)
    }

    fn fresh_node() -> ArxiumDb {
        let db = temp_db("joiner");
        db.write_batch(&GenesisHash(format!("0x{}", hex::encode(GENESIS)))).unwrap();
        commit(&db, 0, 0);
        db
    }

    fn drive(joiner: &ArxiumDb, source: &ArxiumDb, trust: SnapshotTrust) -> Step {
        let peer = libp2p::PeerId::random();
        let mut sync = SnapshotSync::<()>::new(trust);
        let Step::Request(SyncRequest::SnapshotManifest { height }) = sync.on_peer_tip(peer, 3) else {
            panic!("expected a manifest request");
        };
        let mut step = sync.on_manifest(peer, manifest::<()>(source, height));
        loop {
            match step {
                Step::Request(SyncRequest::SnapshotChunk { height, index }) => {
                    step = sync.on_chunk(peer, joiner, height, index, chunk(source, height, index));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn a_joiner_imports_the_anchored_snapshot_and_refuses_a_wrong_anchor() {
        let (source, block, _record) = source_chain();
        let joiner = fresh_node();
        let trust = SnapshotTrust { height: 3, block_hash: block.hash() };
        assert!(matches!(drive(&joiner, &source, trust), Step::Done));
        assert_eq!(joiner.get_tip_height().unwrap(), Some(3));
        assert_eq!(joiner.compute_state_root(&[]).unwrap(), block.state_root);
        assert!(arxd_finality::verify_finality_record(&joiner, &joiner.get_finality_record(3).unwrap().unwrap()));

        // The operator anchored a different hash: the manifest is refused
        // before any chunk is fetched.
        let joiner = fresh_node();
        let wrong = SnapshotTrust { height: 3, block_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".parse().unwrap() };
        assert!(matches!(drive(&joiner, &source, wrong), Step::Retry));
        assert_eq!(joiner.get_tip_height().unwrap(), Some(0));
    }

    #[test]
    fn an_uncertified_or_unreconstructible_height_is_not_served() {
        let (source, _block, _record) = source_chain();
        assert!(manifest::<()>(&source, 2).is_none(), "no certificate at 2");
        assert!(manifest::<()>(&source, 9).is_none(), "above the tip");
        assert!(chunk(&source, 3, 99).is_none(), "past the last chunk");
    }

    #[test]
    fn a_forged_certificate_is_caught_before_import() {
        let (source, block, mut record) = source_chain();
        record.signers = vec![Address::from_pubkey_bytes(&[8u8; 32]).unwrap()];
        let entries = source.state_at(3).unwrap().unwrap();
        let err = verify_certificate_against(&entries, &record, &block).unwrap_err();
        assert!(err.contains("distinct members"), "{err}");
    }
}
