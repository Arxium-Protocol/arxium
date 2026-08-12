use rocksdb::{DB, Direction, IteratorMode, WriteBatch};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use xc_primitives::{AccountEntry, Action, Address, Block, Snapshot};

// ponytail: cap shared by range/history reads so an explorer client can't
// force a full-chain scan in one request; bump if a real UI needs more.
pub const MAX_PAGE_SIZE: usize = 100;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("RocksDB underlying error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("corrupted metadata value in storage")]
    CorruptedMeta,
}

#[derive(Clone)]
pub struct ArxiumDb {
    db: Arc<DB>,
}

/// Anything that can be turned into a set of key-value pairs for storage.
pub trait BatchWritable {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

impl ArxiumDb {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let db = DB::open_default(path)?;
        Ok(Self { db: Arc::new(db) })
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db.get(key).map_err(StorageError::Rocks)
    }

    /// Get the current tip height from the DB.
    pub fn get_tip_height(&self) -> Result<Option<u64>, StorageError> {
        match self.get(b"meta:tip_height")? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::CorruptedMeta)?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Check if the database has been initialized
    pub fn is_initialized(&self) -> Result<bool, StorageError> {
        Ok(self.get(b"meta:height")?.is_some())
    }

    /// Get the chain name recorded at genesis.
    pub fn get_chain_name(&self) -> Result<Option<String>, StorageError> {
        match self.get(b"meta:chain_name")? {
            Some(bytes) => {
                String::from_utf8(bytes).map(Some).map_err(|_| StorageError::CorruptedMeta)
            }
            None => Ok(None),
        }
    }

    /// Write any batch-writable item's entries atomically.
    pub fn write_batch(&self, item: &impl BatchWritable) -> Result<(), StorageError> {
        self.write_batches(&[item as &dyn BatchWritable])
    }

    /// Write several batch-writable items' entries as a single atomic write.
    /// Use this when two items must land together or not at all — e.g. a
    /// block record and the account changes it caused, so a crash can never
    /// leave one committed without the other.
    pub fn write_batches(&self, items: &[&dyn BatchWritable]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        for item in items {
            for (key, value) in item.batch_entries()? {
                batch.put(key, value);
            }
        }
        // Fsync every commit rather than trusting the OS page cache — this
        // chain produces one batch per block on a multi-second interval, not
        // per-transaction, so the extra fsync latency is cheap insurance
        // against a hard crash leaving the on-disk tip ahead of durable data
        // (which would violate the "tip block must exist" invariant on
        // restart, see arxd/node/src/produce.rs).
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(true);
        self.db.write_opt(batch, &opts)?;
        Ok(())
    }

    /// Get the account state from the DB
    pub fn get_account(&self, address: &Address) -> Result<Option<AccountEntry>, StorageError> {
        let key = format!("account:{}", address);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (account, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Get the block from the DB. `P` is the chain-specific action payload
    /// type — callers know it, storage doesn't.
    pub fn get_block<P: DeserializeOwned>(&self, height: u64) -> Result<Option<Block<P>>, StorageError> {
        let key = format!("block:{}", height);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (block, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Look up the height of the block containing a confirmed action, by signature.
    pub fn get_action_block_height(&self, signature: &str) -> Result<Option<u64>, StorageError> {
        let key = format!("action:{}", signature);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::CorruptedMeta)?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Fetch blocks `from..=to` (inclusive), capped at `MAX_PAGE_SIZE`.
    /// Heights are committed sequentially with no gaps (single proposer, no
    /// forks), so this is a plain per-height point lookup, not a scan.
    pub fn get_block_range<P: DeserializeOwned>(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<Block<P>>, StorageError> {
        let to = to.min(from.saturating_add(MAX_PAGE_SIZE as u64 - 1));
        let mut blocks = Vec::new();
        for height in from..=to {
            if let Some(block) = self.get_block(height)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// The round-robin validator set effective as of `height` — the latest
    /// `ValidatorSetSnapshot` recorded at or before `height`. A change
    /// applied in block `H` is recorded effective at `H + 1` (see
    /// `ValidatorSetSnapshot`), so a block's own proposer check always sees
    /// the set as it stood before that block, never one it could vote itself
    /// into. Falls back to an empty set only if genesis never wrote height 0
    /// (shouldn't happen on a bootstrapped chain).
    pub fn get_validator_set_at(&self, height: u64) -> Result<Vec<Address>, StorageError> {
        let prefix = b"validator_set:";
        let seek_key = format!("validator_set:{height:020}");
        let iter = self
            .db
            .iterator(IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (validators, _len) = bincode::serde::decode_from_slice(&value, config)?;
            return Ok(validators);
        }
        Ok(Vec::new())
    }

    /// Look up a block's height by its content hash.
    pub fn get_block_height_by_hash(&self, hash: &str) -> Result<Option<u64>, StorageError> {
        let key = format!("block_hash:{}", hash);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::CorruptedMeta)?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Newest-first page of `address`'s action history, capped at
    /// `MAX_PAGE_SIZE`. `before_height` excludes that height and anything
    /// newer, for paging further back.
    pub fn get_actions_by_address<P: DeserializeOwned>(
        &self,
        address: &Address,
        limit: usize,
        before_height: Option<u64>,
    ) -> Result<Vec<(u64, Action<P>)>, StorageError> {
        let limit = limit.min(MAX_PAGE_SIZE);
        let prefix = format!("addr_action:{}:", address);
        let seek_height = match before_height {
            Some(h) => h.saturating_sub(1),
            None => u64::MAX,
        };
        // ":9999" sorts after any real 4-digit index suffix, so SeekForPrev
        // (what Reverse does) lands on the last real entry at seek_height
        // instead of skipping past it into the previous height.
        let seek_key = format!("{}{:020}:9999", prefix, seek_height);

        let mut results = Vec::new();
        let iter = self
            .db
            .iterator(IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let height_str = &key[prefix.len()..prefix.len() + 20];
            let height: u64 = std::str::from_utf8(height_str)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(StorageError::CorruptedMeta)?;
            let config = bincode::config::standard();
            let (action, _len) = bincode::serde::decode_from_slice(&value, config)?;
            results.push((height, action));
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }
}

impl BatchWritable for Snapshot {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = vec![
            (b"meta:height".to_vec(), self.height.to_be_bytes().to_vec()),
            (
                b"meta:chain_name".to_vec(),
                self.chain_name.as_bytes().to_vec(),
            ),
        ];
        for (address, account) in &self.accounts {
            let key = format!("account:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(account, config)?;
            entries.push((key, value));
        }
        for (address, validator) in &self.validators {
            let key = format!("validator:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(validator, config)?;
            entries.push((key, value));
        }
        let mut genesis_validators: Vec<Address> = self.validators.keys().cloned().collect();
        genesis_validators.sort();
        entries.push((
            b"validator_set:00000000000000000000".to_vec(),
            bincode::serde::encode_to_vec(&genesis_validators, config)?,
        ));
        Ok(entries)
    }
}

/// The round-robin validator set effective starting `effective_height`,
/// written by `xc_executor::accept_block`/`produce_block` whenever a block
/// contains a `ValidatorChange` — one full-set snapshot per change, looked up
/// via `ArxiumDb::get_validator_set_at`. `effective_height` is the changing
/// block's height + 1: the change can't affect who proposes the block that
/// introduced it.
pub struct ValidatorSetSnapshot {
    pub effective_height: u64,
    pub validators: Vec<Address>,
}

impl BatchWritable for ValidatorSetSnapshot {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut sorted = self.validators.clone();
        sorted.sort();
        Ok(vec![(
            format!("validator_set:{:020}", self.effective_height).into_bytes(),
            bincode::serde::encode_to_vec(&sorted, config)?,
        )])
    }
}

impl<P: Serialize> BatchWritable for Block<P> {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();

        let block_key = format!("block:{}", self.height).into_bytes();
        let block_value = bincode::serde::encode_to_vec(self, config)?;

        let mut entries = vec![
            (block_key, block_value),
            (
                b"meta:tip_height".to_vec(),
                self.height.to_be_bytes().to_vec(),
            ),
            (
                format!("block_hash:{}", self.hash()).into_bytes(),
                self.height.to_be_bytes().to_vec(),
            ),
        ];

        for (index, action) in self.actions.iter().enumerate() {
            if let Some(signature) = &action.signature {
                entries.push((
                    format!("action:{}", signature).into_bytes(),
                    self.height.to_be_bytes().to_vec(),
                ));
            }
            entries.push((
                format!(
                    "addr_action:{}:{:020}:{:04}",
                    action.sender, self.height, index
                )
                .into_bytes(),
                bincode::serde::encode_to_vec(action, config)?,
            ));
        }

        Ok(entries)
    }
}

/// A set of account changes to be written atomically. Not account-circuit
/// business logic — just the write-batch shape any circuit that touches
/// accounts (`circuit-account`, `circuit-rwa-asset`, ...) hands back.
pub struct AccountUpdates(pub HashMap<Address, AccountEntry>);

impl BatchWritable for AccountUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (address, entry) in &self.0 {
            let key = format!("account:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(entry, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod explorer_index_tests {
    use super::*;

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-storage-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    fn action(sender: Address, nonce: u64) -> Action<()> {
        Action {
            sender,
            nonce,
            signature: Some(format!("sig-{}", nonce)),
            payload: (),
        }
    }

    fn block(height: u64, actions: Vec<Action<()>>) -> Block<()> {
        Block {
            height,
            parent_hash: "0xparent".into(),
            timestamp: height,
            actions,
            proposer: None,
            signature: None,
        }
    }

    #[test]
    fn block_range_fetches_committed_span() {
        let db = temp_db();
        for h in 0..5 {
            db.write_batch(&block(h, vec![])).unwrap();
        }
        let blocks = db.get_block_range::<()>(1, 3).unwrap();
        assert_eq!(
            blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn block_hash_round_trips_to_height() {
        let db = temp_db();
        let b = block(7, vec![]);
        let hash = b.hash();
        db.write_batch(&b).unwrap();
        assert_eq!(db.get_block_height_by_hash(&hash).unwrap(), Some(7));
        assert_eq!(db.get_block_height_by_hash("0xnope").unwrap(), None);
    }

    #[test]
    fn address_action_history_is_newest_first_and_paginates() {
        let db = temp_db();
        let sender = addr(1);
        let other = addr(2);
        for h in 0..3 {
            db.write_batch(&block(
                h,
                vec![action(sender.clone(), h), action(other.clone(), h)],
            ))
            .unwrap();
        }

        let all = db.get_actions_by_address::<()>(&sender, 10, None).unwrap();
        assert_eq!(
            all.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![2, 1, 0]
        );

        let first_page = db.get_actions_by_address::<()>(&sender, 1, None).unwrap();
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].0, 2);

        let next_page = db
            .get_actions_by_address::<()>(&sender, 10, Some(2))
            .unwrap();
        assert_eq!(
            next_page.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![1, 0]
        );
    }

    #[test]
    fn validator_set_at_returns_latest_snapshot_at_or_before_height() {
        let db = temp_db();
        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![addr(1)],
        })
        .unwrap();
        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 5,
            validators: vec![addr(1), addr(2)],
        })
        .unwrap();
        let mut expected_pair = vec![addr(1), addr(2)];
        expected_pair.sort();

        assert_eq!(db.get_validator_set_at(0).unwrap(), vec![addr(1)]);
        assert_eq!(db.get_validator_set_at(4).unwrap(), vec![addr(1)]);
        assert_eq!(db.get_validator_set_at(5).unwrap(), expected_pair);
        assert_eq!(db.get_validator_set_at(100).unwrap(), expected_pair);
    }
}
