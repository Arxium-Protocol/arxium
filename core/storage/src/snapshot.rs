// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Snapshot sync, storage side: exporting the raw state as of a past height
//! (server), and importing one after verifying it (client). The wire shapes
//! live in `arxd/network`'s `wire` module, whose network loop drives both ends.
//!
//! The server never keeps per-height snapshots. State at `H` is the current
//! state with the per-block undo records for `(H, tip]` applied — the exact
//! algorithm `ArxiumDb::revert_to` runs, minus the write — read under one
//! RocksDB point-in-time snapshot so a block landing mid-export cannot mix
//! two heights. That is why undo records are retained for `UNDO_RETAIN`
//! heights below the watermark instead of being dropped the moment it
//! passes them: it is what makes any recent height servable.
//!
//! The client trusts nothing it downloads. `import_snapshot` recomputes the
//! sparse-Merkle root of the imported state in memory (`xc_poe::root_of`)
//! and requires it to equal the `state_root` of the block the operator's
//! trust anchor named; the network loop has already checked that block's
//! hash against the anchor and its finality certificate against the set the
//! snapshot itself carries. Cosmos's state-sync shape, sized to one node.

use super::*;

/// Undo records are kept this far below the final watermark so a peer can
/// still be served state at any height in `[watermark - UNDO_RETAIN, tip]`.
/// Records are small (a block's touched keys and their prior values), and a
/// joining operator picks a trust height from an explorer, so this is "how
/// stale may a trust anchor be" — ~3h at a 2s slot. ponytail: a constant,
/// not a flag; make it one when an operator asks for a longer window.
pub const UNDO_RETAIN: u64 = 5_000;

/// Encoded bytes per `SnapshotChunk`, kept well under
/// `xc_primitives::MAX_WIRE_MESSAGE_SIZE` (the sync decode cap) with room
/// for bincode framing.
pub const SNAPSHOT_CHUNK_BYTES: usize = 512 * 1024;

/// Splits `entries` into consecutive index ranges of at most
/// `SNAPSHOT_CHUNK_BYTES` (a single oversized entry gets its own range).
/// Deterministic, so the manifest's chunk count and hashes mean the same
/// thing to every peer serving the same height.
pub fn snapshot_chunks(entries: &[(String, Vec<u8>, Vec<u8>)]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let (mut start, mut bytes) = (0usize, 0usize);
    for (i, (cf, key, value)) in entries.iter().enumerate() {
        // Three length prefixes at up to 9 bytes each under bincode varint.
        let size = cf.len() + key.len() + value.len() + 27;
        if bytes + size > SNAPSHOT_CHUNK_BYTES && i > start {
            ranges.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes += size;
    }
    if start < entries.len() {
        ranges.push(start..entries.len());
    }
    ranges
}

/// Per-height and derived rows that describe *this node's* history rather
/// than the chain's state, and so are left out of a snapshot: the importer
/// writes its own tip, watermark, root pointer and the one certificate it
/// verified. Undo, votes and round state below the snapshot height are
/// meaningless to a node that never held those blocks.
fn is_snapshot_key(key: &[u8]) -> bool {
    const EXCLUDED_PREFIXES: [&[u8]; 8] = [
        b"meta:undo:",
        b"meta:finality:",
        b"meta:precommit:",
        b"meta:roundcert:",
        b"meta:roundtimeout:",
        b"meta:dissent:",
        b"meta:block_weight:",
        b"meta:tip_height",
    ];
    const EXCLUDED: [&[u8]; 3] = [MERKLE_ROOT_KEY, FINAL_WATERMARK_KEY, SCHEMA_VERSION_KEY];
    let cf = cf_for_key(key);
    cf != CF_BLOCKS
        && cf != CF_MERKLE
        && !EXCLUDED_PREFIXES.iter().any(|p| key.starts_with(p))
        && !EXCLUDED.contains(&key)
}

impl ArxiumDb {
    /// Every snapshot-able `(column family, key, value)` as of `height`, or
    /// `None` when this node cannot reconstruct that height (above its tip,
    /// or its undo records for `(height, tip]` are gone). Sorted, so two
    /// nodes serving the same height chunk identically.
    ///
    /// ponytail: the whole state is materialised in memory. Fine for a
    /// devnet-scale state; the upgrade path is Cosmos's — a persisted
    /// per-interval checkpoint directory streamed from disk.
    pub fn state_at(&self, height: u64) -> Result<Option<ExportedEntries>, StorageError> {
        let snapshot = self.db.snapshot();
        let tip = match snapshot.get_cf(self.cf(CF_META), b"meta:tip_height")? {
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::CorruptedMeta)?,
            ),
            None => return Ok(None),
        };
        if height > tip {
            return Ok(None);
        }
        let mut entries: BTreeMap<(String, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for cf_name in COLUMN_FAMILIES {
            if *cf_name == *CF_BLOCKS || *cf_name == *CF_MERKLE {
                continue;
            }
            for item in snapshot.iterator_cf(self.cf(cf_name), IteratorMode::Start) {
                let (key, value) = item?;
                if is_snapshot_key(&key) {
                    entries.insert((cf_name.to_string(), key.to_vec()), value.to_vec());
                }
            }
        }
        // Descending, so a key several reverted blocks touched ends at its
        // value as of `height` — `revert_to`'s rule.
        for h in (height + 1..=tip).rev() {
            let Some(bytes) = snapshot.get_cf(self.cf(CF_META), undo_key(h))? else {
                return Ok(None);
            };
            let (record, _len): (UndoRecord, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
            for (key, prior) in record {
                if !is_snapshot_key(&key) {
                    continue;
                }
                let id = (cf_for_key(&key).to_string(), key);
                match prior {
                    Some(value) => entries.insert(id, value),
                    None => entries.remove(&id),
                };
            }
        }
        Ok(Some(
            entries
                .into_iter()
                .map(|((cf, key), value)| (cf, key, value))
                .collect(),
        ))
    }

    /// Replaces this node's state with a downloaded snapshot at `block`'s
    /// height, after checking it is exactly the state that block committed
    /// to. Refuses on anything but a node still at genesis: snapshot sync
    /// exists to skip replay on a *joining* node, never to overwrite history
    /// a node has already executed.
    ///
    /// Checks, in order: the recomputed sparse-Merkle root of every
    /// Merkleized entry equals `block.state_root`; the snapshot's genesis
    /// hash equals this node's (same chain, same BLS signing domain);
    /// `finality` names `block`. The caller has already tied `block` to the
    /// operator's trust anchor and verified `finality`'s aggregate against
    /// the set the snapshot carries — this function trusts those two facts
    /// and nothing else about its inputs.
    ///
    /// Two writes, not one: the wipe (which also drops the trie root pointer,
    /// so the rebuild starts from the empty root) and then the import with
    /// its trie build. A crash in between leaves a node with no tip, which
    /// `bootstrap` treats as uninitialised and re-seeds from genesis — the
    /// sync simply starts over.
    pub fn import_snapshot<P: Serialize + DeserializeOwned>(
        &self,
        entries: &[(String, Vec<u8>, Vec<u8>)],
        block: &Block<P>,
        finality: &FinalityRecord,
    ) -> Result<(), StorageError> {
        let tip = self.get_tip_height()?.unwrap_or(0);
        if tip != 0 {
            return Err(StorageError::SnapshotRejected(format!(
                "node already at height {tip}, not fresh"
            )));
        }
        if finality.height != block.height || finality.block_hash != block.hash() {
            return Err(StorageError::SnapshotRejected(
                "certificate does not name the snapshot block".into(),
            ));
        }
        let leaves: BTreeMap<[u8; 32], Vec<u8>> = entries
            .iter()
            .filter(|(_, key, _)| is_state_key(key))
            .map(|(_, key, value)| (hash_key(key), value.clone()))
            .collect();
        let computed = xc_poe::state_trie::root_of(&leaves);
        let claimed = decode_root(&block.state_root)?;
        if computed != claimed {
            return Err(StorageError::SnapshotRejected(format!(
                "state hashes to 0x{} but block {} committed to {}",
                hex::encode(computed),
                block.height,
                block.state_root
            )));
        }
        let genesis_key = GenesisHashKey.encode();
        let snapshot_genesis = entries
            .iter()
            .find(|(_, key, _)| *key == genesis_key)
            .map(|(_, _, value)| value.clone())
            .ok_or_else(|| {
                StorageError::SnapshotRejected("snapshot carries no genesis hash".into())
            })?;
        let local_genesis = self.get(&genesis_key)?.ok_or_else(|| {
            StorageError::SnapshotRejected("this node has no genesis hash to compare".into())
        })?;
        if snapshot_genesis != local_genesis {
            return Err(StorageError::SnapshotRejected(
                "snapshot is for a different chain".into(),
            ));
        }

        // Wipe: every CF except blocks (genesis stays; it is this chain's),
        // and every meta row but the schema version.
        let mut wipe = WriteBatch::default();
        for cf_name in COLUMN_FAMILIES {
            if *cf_name == *CF_BLOCKS {
                continue;
            }
            for item in self.db.iterator_cf(self.cf(cf_name), IteratorMode::Start) {
                let (key, _) = item?;
                if key.as_ref() != SCHEMA_VERSION_KEY {
                    wipe.delete_cf(self.cf(cf_name), key);
                }
            }
        }
        self.db.write(wipe)?;

        let mut all = entries.to_vec();
        for (key, value) in block.batch_entries()? {
            all.push((cf_for_key(&key).to_string(), key, value));
        }
        for (key, value) in finality.batch_entries()? {
            all.push((CF_META.to_string(), key, value));
        }
        all.push((
            CF_META.to_string(),
            FINAL_WATERMARK_KEY.to_vec(),
            block.height.to_be_bytes().to_vec(),
        ));
        self.write_raw_entries(&all)?;
        debug_assert_eq!(self.merkle_root()?, claimed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::AccountEntry;

    fn temp_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "arxium-test-snapshot-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn accounts(pairs: &[(u8, u128)]) -> AccountUpdates {
        AccountUpdates(
            pairs
                .iter()
                .map(|(n, balance)| {
                    (
                        addr(*n),
                        AccountEntry {
                            balance: *balance,
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        )
    }

    /// One undo-logged block that sets `holder`'s balance, as the executor
    /// commits one.
    fn commit(db: &ArxiumDb, height: u64, holder: u8, balance: u128) -> Block<()> {
        let updates = accounts(&[(holder, balance)]);
        let state_root = db.compute_state_root(&[&updates]).unwrap();
        let parent_hash = db
            .get_block::<()>(height.saturating_sub(1))
            .unwrap()
            .map(|b| b.hash().to_string())
            .unwrap_or_default();
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
        db.write_block_batches(height, &[&updates, &block], true)
            .unwrap();
        block
    }

    #[test]
    fn chunks_are_consecutive_and_bounded() {
        let entries: Vec<(String, Vec<u8>, Vec<u8>)> = (0..1000u32)
            .map(|i| ("cf".into(), i.to_be_bytes().to_vec(), vec![0u8; 2_000]))
            .collect();
        let ranges = snapshot_chunks(&entries);
        assert!(ranges.len() > 1);
        assert_eq!(ranges.first().unwrap().start, 0);
        assert_eq!(ranges.last().unwrap().end, entries.len());
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
        for range in &ranges {
            let bytes: usize = entries[range.clone()]
                .iter()
                .map(|(c, k, v)| c.len() + k.len() + v.len() + 27)
                .sum();
            assert!(bytes <= SNAPSHOT_CHUNK_BYTES);
        }
        assert!(snapshot_chunks(&[]).is_empty());
    }

    /// The in-memory root is the incremental trie's root for the same
    /// contents — otherwise every snapshot would be rejected (or, worse,
    /// a wrong one accepted).
    #[test]
    fn root_of_matches_the_incremental_trie() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batch(&accounts(&[(1, 100), (2, 200), (3, 300)]))
            .unwrap();
        let root = decode_root(&db.compute_state_root(&[]).unwrap()).unwrap();
        let leaves: BTreeMap<[u8; 32], Vec<u8>> = db
            .export_all_entries()
            .unwrap()
            .into_iter()
            .filter(|(_, key, _)| is_state_key(key))
            .map(|(_, key, value)| (hash_key(&key), value))
            .collect();
        assert_eq!(xc_poe::state_trie::root_of(&leaves), root);
        assert_eq!(
            xc_poe::state_trie::root_of(&BTreeMap::new()),
            default_hashes()[256]
        );
    }

    /// `state_at(H)` is the state block `H` committed to, not the tip's.
    #[test]
    fn state_at_rolls_back_through_undo_records() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        for height in 0..=4 {
            commit(&db, height, 1, height as u128 * 10);
        }
        let at_2 = db.state_at(2).unwrap().expect("undo covers it");
        let leaves: BTreeMap<[u8; 32], Vec<u8>> = at_2
            .iter()
            .filter(|(_, key, _)| is_state_key(key))
            .map(|(_, key, value)| (hash_key(key), value.clone()))
            .collect();
        let block_2: Block<()> = db.get_block(2).unwrap().unwrap();
        assert_eq!(
            xc_poe::state_trie::root_of(&leaves),
            decode_root(&block_2.state_root).unwrap()
        );
        assert!(
            at_2.iter()
                .all(|(cf, key, _)| cf != CF_BLOCKS && is_snapshot_key(key))
        );
        assert!(db.state_at(9).unwrap().is_none(), "above the tip");
    }

    /// Import accepts exactly the exported state and refuses a tampered one.
    #[test]
    fn import_snapshot_verifies_before_writing() {
        let source = ArxiumDb::open(&temp_path()).unwrap();
        source.write_batch(&GenesisHash("0x11".into())).unwrap();
        for height in 0..=3 {
            commit(&source, height, 1, height as u128 * 10);
        }
        let entries = source.state_at(3).unwrap().unwrap();
        let block: Block<()> = source.get_block(3).unwrap().unwrap();
        let finality = FinalityRecord {
            height: 3,
            block_hash: block.hash(),
            signers: vec![],
            aggregate_signature: xc_bls::BlsSignature([0u8; 96]),
            ep: [0u8; 32],
        };

        let fresh = || {
            let db = ArxiumDb::open(&temp_path()).unwrap();
            db.write_batch(&GenesisHash("0x11".into())).unwrap();
            commit(&db, 0, 1, 0);
            db
        };

        let mut tampered = entries.clone();
        let (_, _, value) = tampered
            .iter_mut()
            .find(|(_, key, _)| key.starts_with(b"account:"))
            .unwrap();
        value[0] ^= 1;
        let err = fresh()
            .import_snapshot(&tampered, &block, &finality)
            .unwrap_err();
        assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");

        let other_chain = ArxiumDb::open(&temp_path()).unwrap();
        other_chain
            .write_batch(&GenesisHash("0x22".into()))
            .unwrap();
        commit(&other_chain, 0, 1, 0);
        assert!(
            other_chain
                .import_snapshot(&entries, &block, &finality)
                .is_err()
        );

        let db = fresh();
        db.import_snapshot(&entries, &block, &finality).unwrap();
        assert_eq!(db.get_tip_height().unwrap(), Some(3));
        assert_eq!(db.get_final_watermark().unwrap(), 3);
        assert_eq!(db.compute_state_root(&[]).unwrap(), block.state_root);
        assert_eq!(
            db.get_account(&addr(1)).unwrap().map(|e| e.balance),
            Some(30)
        );
        assert!(db.get_finality_record(3).unwrap().is_some());
        // Not fresh any more: a second import is refused.
        assert!(db.import_snapshot(&entries, &block, &finality).is_err());
    }
}
