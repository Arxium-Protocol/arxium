use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options as RocksOptions, WriteBatch};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use xc_bls::{BlsPublicKey, BlsSignature};
use xc_primitives::{AccountEntry, Address, Block, Snapshot, StakeAllocation};
#[cfg(test)]
use xc_primitives::Action;

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

const CF_META: &str = "meta";
const CF_BLOCKS: &str = "blocks";
const CF_ACCOUNTS: &str = "accounts";
const CF_VALIDATORS: &str = "validators";
const COLUMN_FAMILIES: [&str; 4] = [CF_META, CF_BLOCKS, CF_ACCOUNTS, CF_VALIDATORS];

/// Which column family a key belongs in, derived from its prefix rather than
/// tracked separately at each call site — one place to keep in sync with the
/// `format!("prefix:...")` calls below instead of every `get`/`put` call
/// needing its own CF argument.
fn cf_for_key(key: &[u8]) -> &'static str {
    if key.starts_with(b"account:") {
        CF_ACCOUNTS
    } else if key.starts_with(b"block:") || key.starts_with(b"block_hash:") || key.starts_with(b"action:") {
        CF_BLOCKS
    } else if key.starts_with(b"validator") || key.starts_with(b"stake") {
        CF_VALIDATORS
    } else {
        CF_META
    }
}

#[derive(Clone)]
pub struct ArxiumDb {
    db: Arc<DB>,
}

/// Anything that can be turned into a set of key-value pairs for storage.
pub trait BatchWritable {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;

    /// Keys to remove as part of the same atomic batch. Default empty —
    /// most `BatchWritable`s (accounts, blocks, ...) only ever upsert.
    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(Vec::new())
    }
}

impl ArxiumDb {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut db_opts = RocksOptions::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let cf_descriptors = COLUMN_FAMILIES
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, RocksOptions::default()));
        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Column family handle for `name` — always present since `open` creates
    /// all of `COLUMN_FAMILIES` up front.
    fn cf(&self, name: &str) -> &ColumnFamily {
        self.db.cf_handle(name).expect("column family created in ArxiumDb::open")
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db.get_cf(self.cf(cf_for_key(key)), key).map_err(StorageError::Rocks)
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

    /// Whether equivocation evidence against `proposer` at `height` has
    /// already been slashed — replay protection for
    /// `ActionPayload::SubmitEquivocationEvidence`, since the same pair of
    /// conflicting blocks could otherwise be resubmitted for a repeat slash.
    pub fn evidence_processed(&self, height: u64, proposer: &Address) -> Result<bool, StorageError> {
        let key = format!("meta:evidence:{height:020}:{proposer}");
        Ok(self.get(key.as_bytes())?.is_some())
    }

    /// A validator's registered BLS pubkey, if any — set via
    /// `BlsKeyRegistration`, looked up by `arxd/finality` when tallying
    /// precommit votes and verifying the resulting aggregate signature.
    pub fn get_bls_pubkey(&self, address: &Address) -> Result<Option<BlsPublicKey>, StorageError> {
        let key = format!("meta:blskey:{address}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (pubkey, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(pubkey))
            }
            None => Ok(None),
        }
    }

    /// The address currently authorized to submit `JoinValidator`/
    /// `LeaveValidator`/`RegisterBlsKey` on `validator`'s behalf, if any —
    /// set via `OperatorUpdates::authorization`, looked up by `arxd/node`'s
    /// dispatch to gate delegated actions. At most one operator per
    /// validator at a time, mirroring `circuit_staking::apply_stake`'s
    /// single-master invariant.
    pub fn get_operator(&self, validator: &Address) -> Result<Option<Address>, StorageError> {
        let key = format!("meta:operator:{validator}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (operator, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(operator))
            }
            None => Ok(None),
        }
    }

    /// Every validator address currently authorizing `operator` to act for
    /// them — drives a "your validators" listing for a delegated client.
    pub fn get_validators_for_operator(&self, operator: &Address) -> Result<Vec<Address>, StorageError> {
        let key = format!("meta:operator_index:{operator}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (validators, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(validators)
            }
            None => Ok(Vec::new()),
        }
    }

    /// The finality certificate for `height`, if 2/3+ of that height's
    /// validator set has precommitted — see `arxd/finality`.
    pub fn get_finality_record(&self, height: u64) -> Result<Option<FinalityRecord>, StorageError> {
        let key = format!("meta:finality:{height:020}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
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
    ///
    /// Fsyncs before returning — this chain produces one batch per block on
    /// a multi-second interval outside of sync catch-up, so the extra fsync
    /// latency is cheap insurance against a hard crash leaving the on-disk
    /// tip ahead of durable data (which would violate the "tip block must
    /// exist" invariant on restart, see arxd/node/src/produce.rs).
    pub fn write_batches(&self, items: &[&dyn BatchWritable]) -> Result<(), StorageError> {
        self.write_batches_opt(items, true)
    }

    /// Same as `write_batches` but skips the fsync — for replaying a run of
    /// already-finalized blocks during sync catch-up, where a crash just
    /// means re-fetching and re-applying the same page from a peer rather
    /// than losing anything, so paying one fsync per block (vs. one per
    /// ~100-block page, see `arxd/network`'s sync handler) is pure overhead.
    /// Callers on this path must still call `flush_wal` once per page so the
    /// tip is actually durable before it's reported to peers/RPC callers.
    pub fn write_batches_unsynced(&self, items: &[&dyn BatchWritable]) -> Result<(), StorageError> {
        self.write_batches_opt(items, false)
    }

    fn write_batches_opt(&self, items: &[&dyn BatchWritable], sync: bool) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        for item in items {
            for (key, value) in item.batch_entries()? {
                batch.put_cf(self.cf(cf_for_key(&key)), key, value);
            }
            for key in item.batch_deletes()? {
                batch.delete_cf(self.cf(cf_for_key(&key)), key);
            }
        }
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(sync);
        self.db.write_opt(batch, &opts)?;
        Ok(())
    }

    /// Fsyncs the WAL for every write since the last sync — pairs with
    /// `write_batches_unsynced` to turn a page of deferred-fsync block
    /// writes into one durable commit instead of zero.
    pub fn flush_wal(&self) -> Result<(), StorageError> {
        self.db.flush_wal(true)?;
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
        let key = format!("block:{height:020}");
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
            .iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));
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

    /// A single `(master, validator)` stake allocation, if any.
    pub fn get_stake_allocation(
        &self,
        master: &Address,
        validator: &Address,
    ) -> Result<Option<StakeAllocation>, StorageError> {
        let key = format!("stake:{}:{}", master, validator);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (allocation, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(allocation))
            }
            None => Ok(None),
        }
    }

    /// Masters currently staking to `validator`. One-master-per-validator is
    /// an enforced invariant, not just an assumption — callers should treat
    /// a `len() > 1` result as a bug, not a valid multi-delegator state.
    pub fn get_stakes_by_validator(&self, validator: &Address) -> Result<Vec<Address>, StorageError> {
        let key = format!("stake_by_validator:{}", validator);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (masters, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(masters)
            }
            None => Ok(Vec::new()),
        }
    }

    /// All of `master`'s stake allocations, one per validator staked to.
    pub fn get_stakes_by_master(
        &self,
        master: &Address,
    ) -> Result<Vec<(Address, StakeAllocation)>, StorageError> {
        let prefix = format!("stake:{}:", master);
        let mut results = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let validator_str = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|_| StorageError::CorruptedMeta)?;
            let validator = Address::parse(validator_str).map_err(|_| StorageError::CorruptedMeta)?;
            let config = bincode::config::standard();
            let (allocation, _len) = bincode::serde::decode_from_slice(&value, config)?;
            results.push((validator, allocation));
        }
        Ok(results)
    }

    /// Every allocation with an `Unbonding` batch matured as of `height`.
    // ponytail: full `stake:` prefix scan — fine at current scale (matches
    // the doc's "walking skeleton" allowance); add an unlock-height
    // secondary index if allocation count ever makes this a bottleneck.
    pub fn get_allocations_with_unbonding_due(
        &self,
        height: u64,
    ) -> Result<Vec<StakeAllocation>, StorageError> {
        let prefix = b"stake:";
        let mut results = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (allocation, _len): (StakeAllocation, usize) =
                bincode::serde::decode_from_slice(&value, config)?;
            if let Some(unbonding) = &allocation.unbonding {
                if unbonding.unlock_at_height <= height {
                    results.push(allocation);
                }
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

            // ponytail: genesis's `validator.stake` was cosmetic-only — no
            // StakeAllocation was ever materialized, so genesis validators
            // could never be slashed (equivocation silently no-oped) or
            // leave (`stake_lookup` found nothing). Write the same
            // self-stake shape `circuit_staking::apply_stake` would.
            let allocation = StakeAllocation {
                master: address.clone(),
                validator: address.clone(),
                active_amount: validator.stake,
                unbonding: None,
                created_at: self.height,
                updated_at: self.height,
            };
            entries.push((
                format!("stake:{}:{}", address, address).into_bytes(),
                bincode::serde::encode_to_vec(&allocation, config)?,
            ));
            entries.push((
                format!("stake_by_validator:{}", address).into_bytes(),
                bincode::serde::encode_to_vec(&vec![address.clone()], config)?,
            ));
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

        let block_key = format!("block:{:020}", self.height).into_bytes();
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

        for action in self.actions.iter() {
            if let Some(signature) = &action.signature {
                entries.push((
                    format!("action:{}", signature).into_bytes(),
                    self.height.to_be_bytes().to_vec(),
                ));
            }
        }

        Ok(entries)
    }
}

/// Marks equivocation evidence against `proposer` at `height` as processed,
/// so `ArxiumDb::evidence_processed` can reject a resubmission. Written
/// alongside the slash's `AccountUpdates`/`StakeUpdates` in the same atomic
/// batch — see `evidence_processed`.
#[derive(Debug)]
pub struct EvidenceMarker {
    pub height: u64,
    pub proposer: Address,
}

impl BatchWritable for EvidenceMarker {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:evidence:{:020}:{}", self.height, self.proposer).into_bytes();
        Ok(vec![(key, vec![1u8])])
    }
}

/// Registers `address`'s BLS pubkey so `arxd/finality` can verify precommit
/// votes and the resulting aggregate signature against it. Kept separate
/// from `Address` (an Ed25519-derived bech32 identity) rather than folded
/// in — BLS pubkeys are a different byte length and only meaningful once/if
/// the address is in the validator set, not an identity of their own.
#[derive(Debug)]
pub struct BlsKeyRegistration {
    pub address: Address,
    pub pubkey: BlsPublicKey,
}

impl BatchWritable for BlsKeyRegistration {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:blskey:{}", self.address).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(&self.pubkey, config)?;
        Ok(vec![(key, value)])
    }
}

/// Grants or revokes authorization for an operator to submit
/// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey` on one or more
/// validators' behalf (see `arxd/node`'s `AuthorizeOperator`/
/// `RevokeOperator`), plus the full updated reverse-index list for every
/// operator whose list changed as a result — same "caller computes the full
/// new value via a lookup closure, storage just writes it, `None`/empty
/// means delete" shape as `StakeUpdates`.
#[derive(Debug, Default)]
pub struct OperatorUpdates {
    /// `validator -> Some(operator)` to authorize, `validator -> None` to revoke.
    pub authorization: std::collections::BTreeMap<Address, Option<Address>>,
    /// `operator -> full new validator list` (empty means delete).
    pub operator_index: std::collections::BTreeMap<Address, Vec<Address>>,
}

impl BatchWritable for OperatorUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (validator, operator) in &self.authorization {
            if let Some(operator) = operator {
                let key = format!("meta:operator:{validator}").into_bytes();
                let value = bincode::serde::encode_to_vec(operator, config)?;
                entries.push((key, value));
            }
        }
        for (operator, validators) in &self.operator_index {
            if !validators.is_empty() {
                let key = format!("meta:operator_index:{operator}").into_bytes();
                let value = bincode::serde::encode_to_vec(validators, config)?;
                entries.push((key, value));
            }
        }
        Ok(entries)
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut deletes = Vec::new();
        for (validator, operator) in &self.authorization {
            if operator.is_none() {
                deletes.push(format!("meta:operator:{validator}").into_bytes());
            }
        }
        for (operator, validators) in &self.operator_index {
            if validators.is_empty() {
                deletes.push(format!("meta:operator_index:{operator}").into_bytes());
            }
        }
        Ok(deletes)
    }
}

/// A block finality certificate: proof 2/3+ of `height`'s validator set
/// independently BLS-signed `block_hash`. Stored as its own record rather
/// than a `Block<P>` field — it's produced in a second round after the
/// block already propagated, so embedding it would mean mutating an
/// already-gossiped/stored block.
#[derive(Serialize, Deserialize)]
pub struct FinalityRecord {
    pub height: u64,
    pub block_hash: String,
    pub signers: Vec<Address>,
    pub aggregate_signature: BlsSignature,
}

impl BatchWritable for FinalityRecord {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:finality:{:020}", self.height).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// A set of account changes to be written atomically. Not account-circuit
/// business logic — just the write-batch shape any circuit that touches
/// accounts (`circuit-account`, `circuit-rwa-asset`, ...) hands back.
#[derive(Debug, Default)]
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

/// A set of stake-allocation changes to be written atomically alongside a
/// block, same reasoning as `AccountUpdates`. `allocations` maps
/// `(master, validator) -> Some(allocation)` for an upsert or `None` for a
/// removal (fully slashed / fully resolved). `validator_index` maps
/// `validator -> full new master list` for that validator's
/// `stake_by_validator:` row — an empty list removes the row.
#[derive(Debug, Default)]
pub struct StakeUpdates {
    pub allocations: std::collections::BTreeMap<(Address, Address), Option<StakeAllocation>>,
    pub validator_index: std::collections::BTreeMap<Address, Vec<Address>>,
}

impl BatchWritable for StakeUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for ((master, validator), allocation) in &self.allocations {
            if let Some(allocation) = allocation {
                let key = format!("stake:{}:{}", master, validator).into_bytes();
                let value = bincode::serde::encode_to_vec(allocation, config)?;
                entries.push((key, value));
            }
        }
        for (validator, masters) in &self.validator_index {
            if !masters.is_empty() {
                let key = format!("stake_by_validator:{}", validator).into_bytes();
                let value = bincode::serde::encode_to_vec(masters, config)?;
                entries.push((key, value));
            }
        }
        Ok(entries)
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut deletes = Vec::new();
        for ((master, validator), allocation) in &self.allocations {
            if allocation.is_none() {
                deletes.push(format!("stake:{}:{}", master, validator).into_bytes());
            }
        }
        for (validator, masters) in &self.validator_index {
            if masters.is_empty() {
                deletes.push(format!("stake_by_validator:{}", validator).into_bytes());
            }
        }
        Ok(deletes)
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

    #[test]
    fn genesis_validator_gets_a_real_self_stake_allocation() {
        let db = temp_db();
        let mut validators = std::collections::BTreeMap::new();
        validators.insert(addr(1), xc_primitives::ValidatorEntry { stake: 1_000_000 });
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts: Default::default(),
            validators,
            boot_nodes: vec![],
        })
        .unwrap();

        let allocation = db.get_stake_allocation(&addr(1), &addr(1)).unwrap().unwrap();
        assert_eq!(allocation.active_amount, 1_000_000);
        assert_eq!(db.get_stakes_by_validator(&addr(1)).unwrap(), vec![addr(1)]);
    }
}
