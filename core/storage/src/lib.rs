// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options as RocksOptions, WriteBatch};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use xc_bls::{BlsPublicKey, BlsSignature};
use xc_circuit::{
    AccountAssetsKey, AccountKey, AssetBalanceKey, AssetIndexKey, AssetKey,
    AttestorRecordKey, BlsKeyKey, GovernorKey, KeySpec, KvRead, StakeByValidatorKey, StakeKey,
};
use xc_circuit::{CF_ACCOUNTS, CF_ASSETS, CF_ATTESTORS, CF_BLOCKS, CF_META, CF_VALIDATORS};
use xc_primitives::{
    stake_subaccount, AccountEntry, Address, Asset, AttestorRecord, Block, Snapshot, StakeAllocation,
};
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

    #[error(
        "database schema version {found} is newer than this binary supports ({supported}) — upgrade the binary before opening this database"
    )]
    SchemaTooNew { found: u32, supported: u32 },

    #[error(
        "database schema version {found} predates what this binary requires ({supported}) and no migration from {found} is implemented — wipe and resync, or run a binary built for version {found}"
    )]
    SchemaTooOld { found: u32, supported: u32 },

    #[error("not a valid state root (expected \"0x\" + 64 hex chars): {0}")]
    InvalidRoot(String),
}

/// Content-addressed Merkle-trie nodes (`B3`) — keyed by node hash, so a
/// fresh vs. legacy DB is entirely a matter of whether this CF exists yet,
/// gated by `SCHEMA_VERSION` below rather than a runtime probe.
const CF_MERKLE: &str = "merkle";

const COLUMN_FAMILIES: [&str; 7] =
    [CF_META, CF_BLOCKS, CF_ACCOUNTS, CF_VALIDATORS, CF_MERKLE, CF_ASSETS, CF_ATTESTORS];

/// On-disk layout version this binary understands — covers column-family
/// layout and key encoding (`cf_for_key`, `Block`'s bincode shape, etc; NOT
/// the higher-level `Block.state_root`/consensus-format changes tracked
/// separately). Bump this and add a migration arm in `migrate_schema` below
/// whenever one of those changes (e.g. `CF_BLOCKS`'s planned re-keying for
/// finality-gated commit).
///
/// ponytail: no migration runner exists yet because no forward migration is
/// implemented — `open` below fails closed on any mismatch (older *or*
/// newer) rather than guessing, which is the actual prerequisite (a version
/// marker that makes silent drift impossible); the forward-migration code
/// itself is naturally added the day it's actually needed, in
/// `migrate_schema`.
///
/// Bumped 1 -> 2 for `B3`: `compute_state_root` moved from a full
/// `CF_ACCOUNTS`+`CF_VALIDATORS` rescan to an incremental Merkle trie backed
/// by the new `CF_MERKLE` CF (see `compute_state_root`'s doc comment). A
/// version-1 DB has no trie built for its already-written state, so it's
/// refused rather than silently treated as an empty trie — wipe and resync
/// on a matching binary, same policy `Arxium_OpenItems.md` §7 already
/// documents for this class of change.
///
/// Bumped 2 -> 3 for regulated-asset balances (`CF_ASSETS`) joining the
/// state trie via `is_state_key` — a version-2 DB's trie doesn't include
/// whatever `asset_balance:` entries it already has, same "wipe and resync"
/// policy as the 1 -> 2 bump above, deliberately accepted before mainnet.
///
/// Bumped 3 -> 4 for the attestor registry (`CF_ATTESTORS`) joining the
/// state trie the same way — attestor-set membership gates
/// `GrantAttestation`/`RevokeAttestation`, so it has to be provable in the
/// state root from the moment it becomes runtime-mutable, same "wipe and
/// resync" policy as the prior two bumps.
pub const SCHEMA_VERSION: u32 = 4;

const SCHEMA_VERSION_KEY: &[u8] = b"meta:schema_version";
const MERKLE_ROOT_KEY: &[u8] = b"meta:merkle_root";

/// Whether `key` is covered by the `B3` state trie / `compute_state_root` —
/// `CF_ACCOUNTS`/`CF_VALIDATORS`/`CF_ASSETS`, i.e. every balance-bearing CF.
fn is_state_key(key: &[u8]) -> bool {
    matches!(cf_for_key(key), CF_ACCOUNTS | CF_VALIDATORS | CF_ASSETS | CF_ATTESTORS)
}

/// Parses a `Block.state_root`-shaped string (`"0x"` + 64 hex chars, as
/// produced by `compute_state_root`) back into the raw root `prove` and
/// `trie_root_after` operate on.
fn decode_root(root: &str) -> Result<[u8; 32], StorageError> {
    let hex_part = root.strip_prefix("0x").unwrap_or(root);
    let bytes = hex::decode(hex_part).map_err(|_| StorageError::InvalidRoot(root.to_string()))?;
    bytes.try_into().map_err(|_| StorageError::InvalidRoot(root.to_string()))
}

// The trie's hash functions, default-subtree table, and proof
// type/verification live in `xc_poe::state_trie` — not duplicated here — so
// `arx-verify` and other no-RocksDB parties can check a proof this crate
// produces without depending on `xc-storage` (see that module's doc
// comment). Both directions of a proof round-trip (`prove` below builds one,
// `xc_poe::state_trie::verify_proof` checks it) must use the exact same
// hashing, which a shared definition guarantees.
use xc_poe::state_trie::{InclusionProof, bit_at, default_hashes, hash_key, internal_hash, leaf_hash};

/// Which column family a key belongs in, derived from its prefix rather than
/// tracked separately at each call site — one place to keep in sync with the
/// `format!("prefix:...")` calls below instead of every `get`/`put` call
/// needing its own CF argument.
///
/// `CF_MERKLE` is the one exception to "prefix": its keys are raw 32-byte
/// node hashes, not `format!`-built strings, so they're recognized by shape
/// instead — safe because every other key in this codebase is a
/// human-readable ASCII prefix well over 32 bytes long, so a real 32-byte
/// key can only be a merkle node hash. This branch only matters for
/// `arxd/genesis`'s raw-artifact export/verify round trip, which tags every
/// entry with its CF generically and cross-checks it here; ordinary reads
/// and writes always name `CF_MERKLE` explicitly and never reach this
/// function with a node-hash key.
pub fn cf_for_key(key: &[u8]) -> &'static str {
    if key.starts_with(b"account:") {
        CF_ACCOUNTS
    } else if key.starts_with(b"block:") || key.starts_with(b"block_hash:") || key.starts_with(b"action:") {
        CF_BLOCKS
    } else if key.starts_with(b"validator") || key.starts_with(b"stake") {
        CF_VALIDATORS
    } else if key.starts_with(b"asset_balance:") {
        CF_ASSETS
    } else if key.starts_with(b"attestor_record:") {
        CF_ATTESTORS
    } else if key.len() == 32 {
        CF_MERKLE
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
        let this = Self { db: Arc::new(db) };
        this.check_schema_version()?;
        Ok(this)
    }

    /// Stamps a fresh (or pre-marker legacy) database with `SCHEMA_VERSION`,
    /// or refuses to open one from a mismatched binary. See `SCHEMA_VERSION`
    /// for what "schema" covers here.
    fn check_schema_version(&self) -> Result<(), StorageError> {
        let meta = self.cf(CF_META);
        match self.db.get_cf(meta, SCHEMA_VERSION_KEY)? {
            None => {
                self.db.put_cf(meta, SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_le_bytes())?;
                Ok(())
            }
            Some(bytes) => {
                let arr: [u8; 4] = bytes.as_slice().try_into().map_err(|_| StorageError::CorruptedMeta)?;
                let found = u32::from_le_bytes(arr);
                if found == SCHEMA_VERSION {
                    Ok(())
                } else if found > SCHEMA_VERSION {
                    Err(StorageError::SchemaTooNew { found, supported: SCHEMA_VERSION })
                } else {
                    Err(StorageError::SchemaTooOld { found, supported: SCHEMA_VERSION })
                }
            }
        }
    }

    /// Column family handle for `name` — always present since `open` creates
    /// all of `COLUMN_FAMILIES` up front.
    fn cf(&self, name: &str) -> &ColumnFamily {
        self.db.cf_handle(name).expect("column family created in ArxiumDb::open")
    }

    /// Writes a consistent, point-in-time copy of the whole database to
    /// `path` (which must not already exist) using RocksDB's native
    /// checkpoint mechanism — hardlinks for existing SST files plus a small
    /// copy of in-memory state, so it's cheap regardless of chain history
    /// size. The result is a standalone, directly-openable `ArxiumDb`
    /// directory: bootstrapping a new node from one means pointing its data
    /// dir at a copy of this output instead of replaying every block from
    /// genesis.
    ///
    /// ponytail: this is a trust-the-source bootstrap shortcut, not a
    /// consensus-verified state sync — `Block` carries no state root a new
    /// node could check a snapshot against, so nothing here proves the
    /// snapshot matches what the network actually finalized. Upgrade path:
    /// add a state root to the block header, then a downloading node can
    /// verify a snapshot against a finalized block instead of trusting
    /// whoever handed it the directory.
    pub fn export_checkpoint(&self, path: &Path) -> Result<(), StorageError> {
        rocksdb::checkpoint::Checkpoint::new(&self.db)?.create_checkpoint(path)?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db.get_cf(self.cf(cf_for_key(key)), key).map_err(StorageError::Rocks)
    }
}

impl KvRead for ArxiumDb {
    type Error = StorageError;

    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, StorageError> {
        match self.get(&key.encode())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (value, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

impl ArxiumDb {
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

    /// A validator's *currently* registered BLS pubkey, if any — set via
    /// `BlsKeyRegistration`. Only safe for live, present-tense reads (e.g.
    /// reporting `validators_with_bls_key` over RPC); anything that verifies
    /// a signature which could have been produced at an earlier height must
    /// use `get_bls_pubkey_at` instead, since a key rotation would otherwise
    /// silently reinterpret an old signature against the wrong key.
    pub fn get_bls_pubkey(&self, address: &Address) -> Result<Option<BlsPublicKey>, StorageError> {
        KvRead::get(self, &BlsKeyKey(address))
    }

    /// `address`'s BLS pubkey as of `height` — the latest `BlsKeyRegistration`
    /// with `effective_height <= height` (same reverse-seek pattern and
    /// "recorded effective one block after the action that caused it" rule
    /// as `get_validator_set_at`). Verifying a round certificate or a
    /// finality/precommit vote against `get_bls_pubkey` (the *current* key)
    /// instead of this would make verification depend on whether the signer
    /// has rotated its key since — the same non-determinism bug fixed for
    /// round eligibility itself, reintroduced through the key lookup instead
    /// of the round lookup. A syncing node replaying an old height must
    /// reach the same verdict as the node that originally verified it live.
    pub fn get_bls_pubkey_at(&self, address: &Address, height: u64) -> Result<Option<BlsPublicKey>, StorageError> {
        let prefix = format!("meta:blskey_hist:{address}:").into_bytes();
        let seek_key = format!("meta:blskey_hist:{address}:{height:020}").into_bytes();
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(&seek_key, Direction::Reverse));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (pubkey, _len) = bincode::serde::decode_from_slice(&value, config)?;
            return Ok(Some(pubkey));
        }
        Ok(None)
    }

    // ponytail: linear scan over the `meta:blskey:` prefix, fine at
    // devnet validator-set scale — add a pubkey->address reverse index if
    // the validator set ever grows enough to make this a bottleneck.
    /// Address already holding `pubkey`, if any — used to reject a second
    /// validator registering the same BLS key.
    pub fn bls_pubkey_owner(&self, pubkey: &BlsPublicKey) -> Result<Option<Address>, StorageError> {
        let prefix = b"meta:blskey:";
        let iter = self.db.iterator_cf(self.cf(CF_META), IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (existing, _len): (BlsPublicKey, usize) = bincode::serde::decode_from_slice(&value, config)?;
            if &existing == pubkey {
                let address_str = std::str::from_utf8(&key[prefix.len()..]).map_err(|_| StorageError::CorruptedMeta)?;
                let address = Address::parse(address_str).map_err(|_| StorageError::CorruptedMeta)?;
                return Ok(Some(address));
            }
        }
        Ok(None)
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

    /// One attestor's registry record, if `attestor` is currently registered.
    pub fn get_attestor_record(&self, attestor: &Address) -> Result<Option<AttestorRecord>, StorageError> {
        KvRead::get(self, &AttestorRecordKey(attestor))
    }

    /// Every registered attestor, as `(address, record)` pairs. Registry
    /// entries are small and governance-sized (nowhere near asset or account
    /// volume), so this scans `CF_ATTESTORS` directly rather than
    /// maintaining a separate `CF_META` listing index the way assets do.
    pub fn list_attestors(&self) -> Result<Vec<(Address, AttestorRecord)>, StorageError> {
        let config = bincode::config::standard();
        let mut attestors = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_ATTESTORS), IteratorMode::Start) {
            let (key, value) = item?;
            let key_str = std::str::from_utf8(&key).map_err(|_| StorageError::CorruptedMeta)?;
            let address_str = key_str
                .strip_prefix("attestor_record:")
                .ok_or(StorageError::CorruptedMeta)?;
            let address = Address::parse(address_str).map_err(|_| StorageError::CorruptedMeta)?;
            let (record, _): (AttestorRecord, _) = bincode::serde::decode_from_slice(&value, config)?;
            attestors.push((address, record));
        }
        Ok(attestors)
    }

    /// A registered asset's registry record (`issuer`/`compliance_required`),
    /// if `asset_id` has been registered via `RegisterAsset`.
    pub fn get_asset(&self, asset_id: &str) -> Result<Option<Asset>, StorageError> {
        KvRead::get(self, &AssetKey(asset_id))
    }

    /// `owner`'s balance of `asset_id`, defaulting to 0 if never minted.
    pub fn get_asset_balance(&self, asset_id: &str, owner: &Address) -> Result<u128, StorageError> {
        Ok(KvRead::get(self, &AssetBalanceKey { asset_id, owner })?.unwrap_or(0))
    }

    /// Every registered asset id, in registration order. Empty on a chain
    /// where `RegisterAsset` has never run.
    pub fn list_asset_ids(&self) -> Result<Vec<String>, StorageError> {
        Ok(KvRead::get(self, &AssetIndexKey)?.unwrap_or_default())
    }

    /// Every registered asset's registry record. Drives an "assets on this
    /// chain" listing; a wallet needs `compliance_required` per asset to know
    /// which balances are gated before it offers a transfer.
    pub fn list_assets(&self) -> Result<Vec<Asset>, StorageError> {
        let mut assets = Vec::new();
        for asset_id in self.list_asset_ids()? {
            // An id in the index with no record would mean the two writes in
            // `AssetIndexUpdates`/`Asset` came apart, which they cannot: both
            // go in one atomic batch. Skipped rather than errored so a single
            // bad row can't take out the whole listing.
            if let Some(asset) = self.get_asset(&asset_id)? {
                assets.push(asset);
            }
        }
        Ok(assets)
    }

    /// Every asset id `owner` has a balance row for, including rows that have
    /// since gone to zero — a balance is never deleted (see
    /// `apply_asset_balances`), so neither is its index entry.
    pub fn get_account_assets(&self, owner: &Address) -> Result<Vec<String>, StorageError> {
        Ok(KvRead::get(self, &AccountAssetsKey(owner))?.unwrap_or_default())
    }

    /// The index rows implied by one block's asset effects: the registry list
    /// grows by any newly registered ids, and each owner touched by a balance
    /// change gains the ids it was touched for.
    ///
    /// Same shape as `OperatorUpdates` — the caller reads the current value
    /// and hands storage the *full* new list, because `BatchWritable` has no
    /// read access of its own. Returns only rows that actually change, so a
    /// block with no asset activity writes nothing.
    pub fn asset_index_updates(
        &self,
        registrations: &[Asset],
        balances: &AssetBalanceUpdates,
    ) -> Result<AssetIndexUpdates, StorageError> {
        let mut updates = AssetIndexUpdates::default();

        if !registrations.is_empty() {
            let mut ids = self.list_asset_ids()?;
            let before = ids.len();
            for asset in registrations {
                if !ids.contains(&asset.asset_id) {
                    ids.push(asset.asset_id.clone());
                }
            }
            if ids.len() != before {
                updates.registry = Some(ids);
            }
        }

        // Grouped by owner first so an owner touched for several assets in one
        // block is read once, not once per asset.
        let mut by_owner: BTreeMap<&Address, Vec<&String>> = BTreeMap::new();
        for (asset_id, owner) in balances.0.keys() {
            by_owner.entry(owner).or_default().push(asset_id);
        }
        for (owner, asset_ids) in by_owner {
            let mut held = self.get_account_assets(owner)?;
            let before = held.len();
            for asset_id in asset_ids {
                if !held.contains(asset_id) {
                    held.push(asset_id.clone());
                }
            }
            if held.len() != before {
                updates.owners.insert(owner.clone(), held);
            }
        }

        Ok(updates)
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
    /// The round `eligible_proposer` should use for `height`: one past the
    /// highest round with a persisted `RoundCertificate`, or `0` if none
    /// exists yet. See `RoundCertificate`'s doc comment for why this — not a
    /// block-claimed value — is the source of truth for round.
    ///
    /// ponytail: a linear scan over this height's certificates, not a
    /// denormalized "current round" counter kept in sync on every write —
    /// round certificates are rare (only formed on an actual timeout) and
    /// small in number per height, so the scan is cheap and there is no
    /// second value that can drift from the certificates themselves.
    pub fn current_round(&self, height: u64) -> Result<u32, StorageError> {
        let prefix = format!("meta:roundcert:{height:020}:");
        let iter = self.db.iterator_cf(self.cf(CF_META), IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        let mut highest_certified: Option<u32> = None;
        for item in iter {
            let (key, _value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let round_str =
                std::str::from_utf8(&key[prefix.len()..]).map_err(|_| StorageError::CorruptedMeta)?;
            let round: u32 = round_str.parse().map_err(|_| StorageError::CorruptedMeta)?;
            highest_certified = Some(highest_certified.map_or(round, |m| m.max(round)));
        }
        Ok(highest_certified.map_or(0, |m| m + 1))
    }

    pub fn get_round_certificate(&self, height: u64, round: u32) -> Result<Option<RoundCertificate>, StorageError> {
        let key = format!("meta:roundcert:{height:020}:{round}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (record, _len): (RoundCertificate, usize) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

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
        let mut state_changes: BTreeMap<[u8; 32], Option<Vec<u8>>> = BTreeMap::new();
        for item in items {
            for (key, value) in item.batch_entries()? {
                if is_state_key(&key) {
                    state_changes.insert(hash_key(&key), Some(value.clone()));
                }
                batch.put_cf(self.cf(cf_for_key(&key)), key, value);
            }
            for key in item.batch_deletes()? {
                if is_state_key(&key) {
                    state_changes.insert(hash_key(&key), None);
                }
                batch.delete_cf(self.cf(cf_for_key(&key)), key);
            }
        }
        if !state_changes.is_empty() {
            self.trie_root_after(&state_changes, Some(&mut batch))?;
        }
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(sync);
        self.db.write_opt(batch, &opts)?;
        Ok(())
    }

    /// Dumps every `(column_family, key, value)` triple currently on disk —
    /// used by the genesis-artifact generator to snapshot a freshly-written
    /// scratch DB into a raw artifact, rather than re-deriving keys/values
    /// from `Snapshot` a second time and risking the two encodings drifting
    /// apart.
    pub fn export_all_entries(&self) -> Result<Vec<(String, Vec<u8>, Vec<u8>)>, StorageError> {
        let mut entries = Vec::new();
        for cf_name in COLUMN_FAMILIES {
            for item in self.db.iterator_cf(self.cf(cf_name), IteratorMode::Start) {
                let (key, value) = item?;
                entries.push((cf_name.to_string(), key.to_vec(), value.to_vec()));
            }
        }
        Ok(entries)
    }

    /// Loads pre-tagged `(column_family, key, value)` triples as a single
    /// atomic batch — the counterpart to `export_all_entries`, used by
    /// `bootstrap` to load a genesis artifact directly instead of replaying
    /// `Snapshot`/BLS-registration/genesis-block construction on every first
    /// boot.
    pub fn write_raw_entries(&self, entries: &[(String, Vec<u8>, Vec<u8>)]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut state_changes: BTreeMap<[u8; 32], Option<Vec<u8>>> = BTreeMap::new();
        for (cf_name, key, value) in entries {
            if matches!(cf_name.as_str(), CF_ACCOUNTS | CF_VALIDATORS | CF_ASSETS) {
                state_changes.insert(hash_key(key), Some(value.clone()));
            }
            batch.put_cf(self.cf(cf_name), key, value);
        }
        if !state_changes.is_empty() {
            self.trie_root_after(&state_changes, Some(&mut batch))?;
        }
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(true);
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

    /// Root committing to the full current account and validator/stake
    /// state — balances, nonces, stake allocations, and the validator set —
    /// so a snapshot recipient can recompute it from a full state dump and
    /// check it against a block's `state_root` instead of trusting the
    /// source, the gap called out in `Arxium_OpenItems.md`.
    ///
    /// `overlay` lets a caller ask "what would the root be *after* these
    /// pending writes land" without committing them first — both a proposer
    /// (deciding what to sign) and a validator (checking a peer's claim
    /// before writing anything) need the post-block root before the block
    /// itself is durable.
    ///
    /// `B3`: an incremental sparse Merkle trie over `CF_ACCOUNTS` +
    /// `CF_VALIDATORS`, keyed by `SHA256(raw key)` as a 256-bit path —
    /// content-addressed nodes live in `CF_MERKLE`, the current committed
    /// root in `CF_META` (`MERKLE_ROOT_KEY`). Updating touches
    /// `O(changed keys × 256)` nodes regardless of total state size, instead
    /// of the old full-state rescan — see `Arxium_OpenItems.md` §4 for the
    /// growth problem this replaces. `write_batches`/`write_raw_entries`
    /// keep the persisted trie in lockstep with every write to those two CFs
    /// automatically (filtered via `is_state_key`), so this is the only
    /// place that needs to know the trie exists.
    ///
    /// `overlay` lets a caller ask "what would the root be *after* these
    /// pending writes land" without committing them first — both a proposer
    /// (deciding what to sign) and a validator (checking a peer's claim
    /// before writing anything) need the post-block root before the block
    /// itself is durable. This computes against the *persisted* trie plus
    /// `overlay` purely in memory, staging nothing.
    ///
    /// Deliberately excludes BLS-key registrations, evidence markers, and
    /// operator authorizations (`CF_META`) — those aren't balance-bearing
    /// and can be folded in later if a real light-client use case needs them
    /// covered too.
    pub fn compute_state_root(&self, overlay: &[&dyn BatchWritable]) -> Result<String, StorageError> {
        let mut state_changes: BTreeMap<[u8; 32], Option<Vec<u8>>> = BTreeMap::new();
        for writable in overlay {
            for (key, value) in writable.batch_entries()? {
                if is_state_key(&key) {
                    state_changes.insert(hash_key(&key), Some(value));
                }
            }
            for key in writable.batch_deletes()? {
                if is_state_key(&key) {
                    state_changes.insert(hash_key(&key), None);
                }
            }
        }
        let root = self.trie_root_after(&state_changes, None)?;
        Ok(format!("0x{}", hex::encode(root)))
    }

    /// Reads the currently *persisted* trie root, or the canonical
    /// empty-trie root if none has been written yet (a fresh DB, or one that
    /// predates `B3` — unreachable in practice since `SCHEMA_VERSION` refuses
    /// to open those, but this stays correct either way).
    fn merkle_root(&self) -> Result<[u8; 32], StorageError> {
        match self.db.get_cf(self.cf(CF_META), MERKLE_ROOT_KEY)? {
            Some(bytes) => bytes.as_slice().try_into().map_err(|_| StorageError::CorruptedMeta),
            None => Ok(default_hashes()[256]),
        }
    }

    /// An internal node's two children, by its own hash — from `overrides`
    /// (a node this same call already produced) if present, else from
    /// `CF_MERKLE`. Only ever called for a hash already known not to be a
    /// default/empty-subtree hash, so a miss here means the trie is
    /// corrupted, not merely sparse.
    fn node_children(&self, hash: &[u8; 32], overrides: &HashMap<[u8; 32], Vec<u8>>) -> Result<([u8; 32], [u8; 32]), StorageError> {
        let bytes = match overrides.get(hash) {
            Some(bytes) => bytes.clone(),
            None => self.db.get_cf(self.cf(CF_MERKLE), hash)?.ok_or(StorageError::CorruptedMeta)?,
        };
        if bytes.len() != 64 {
            return Err(StorageError::CorruptedMeta);
        }
        let left: [u8; 32] = bytes[..32].try_into().expect("checked len above");
        let right: [u8; 32] = bytes[32..].try_into().expect("checked len above");
        Ok((left, right))
    }

    /// Descends from `root` along `key_hash`'s 256-bit path, recording the
    /// sibling at each level (index 0 = nearest the root) plus the node
    /// found at the leaf level — either an actual leaf hash or
    /// `default_hashes()[0]` if `key_hash` isn't present under `root`. Shared
    /// by `trie_root_after` (which then climbs back up with a new leaf in
    /// place) and `prove` (which stops here — the descent path *is* the
    /// inclusion/non-inclusion proof).
    fn descend(
        &self,
        root: [u8; 32],
        key_hash: &[u8; 32],
        overrides: &HashMap<[u8; 32], Vec<u8>>,
    ) -> Result<([[u8; 32]; 256], [u8; 32]), StorageError> {
        let defaults = default_hashes();
        let mut siblings = [[0u8; 32]; 256];
        let mut node = root;
        for level in 0..256 {
            let depth = 256 - level;
            if node == defaults[depth] {
                siblings[level] = defaults[depth - 1];
                node = defaults[depth - 1];
            } else {
                let (left, right) = self.node_children(&node, overrides)?;
                let (child, sibling) = if bit_at(key_hash, level) == 0 { (left, right) } else { (right, left) };
                siblings[level] = sibling;
                node = child;
            }
        }
        Ok((siblings, node))
    }

    /// Builds an inclusion (or non-inclusion) proof for `key` against `root`
    /// — a hex-encoded root from a `Block.state_root`/`compute_state_root`
    /// call, current or historical: nodes are content-addressed and never
    /// pruned (see `CF_MERKLE`'s doc comment), so any root this node has ever
    /// computed can still be proved against. Verify with
    /// `xc_poe::state_trie::verify_proof` — this is Part 3 Stage 1's
    /// prerequisite for both bisection (proving the handful of state keys a
    /// disputed action touched) and a light wallet (proving its own balance
    /// without trusting the node that reports it).
    pub fn prove(&self, key: &[u8], root: &str) -> Result<InclusionProof, StorageError> {
        let root_bytes = decode_root(root)?;
        let key_hash = hash_key(key);
        let (siblings, leaf_node) = self.descend(root_bytes, &key_hash, &HashMap::new())?;
        let value = if leaf_node == default_hashes()[0] {
            None
        } else {
            let content =
                self.db.get_cf(self.cf(CF_MERKLE), leaf_node)?.ok_or(StorageError::CorruptedMeta)?;
            if content.len() < 32 {
                return Err(StorageError::CorruptedMeta);
            }
            Some(content[32..].to_vec())
        };
        Ok(InclusionProof { key_hash, value, siblings: siblings.to_vec() })
    }

    /// Applies `changes` (key-hash -> new value, or `None` to delete) to the
    /// persisted trie and returns the resulting root. When `batch` is
    /// `Some`, every newly-created node (and the root pointer, if anything
    /// changed) is staged into it — the caller is responsible for actually
    /// writing that batch atomically alongside the raw `CF_ACCOUNTS`/
    /// `CF_VALIDATORS` entries it was derived from, so the trie can never
    /// observably desync from the state it commits to. When `batch` is
    /// `None`, nothing is persisted — this is the speculative preview path
    /// `compute_state_root` uses.
    fn trie_root_after(
        &self,
        changes: &BTreeMap<[u8; 32], Option<Vec<u8>>>,
        mut batch: Option<&mut WriteBatch>,
    ) -> Result<[u8; 32], StorageError> {
        let defaults = default_hashes();
        let mut root = self.merkle_root()?;
        let mut overrides: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

        for (key_hash, new_value) in changes {
            // `defaults[depth]` short-circuits an entirely-empty subtree
            // without ever touching storage during descent, which is what
            // keeps an update to one key cheap regardless of how much of the
            // trie is still empty.
            let (siblings, _leaf_node) = self.descend(root, key_hash, &overrides)?;

            // Climb back up, recomputing every node on the path with the new
            // leaf in place of the old one.
            let mut current = match new_value {
                Some(value) => {
                    let leaf = leaf_hash(key_hash, value);
                    let content = [key_hash.as_slice(), value.as_slice()].concat();
                    if let Some(batch) = batch.as_deref_mut() {
                        batch.put_cf(self.cf(CF_MERKLE), leaf, &content);
                    }
                    overrides.insert(leaf, content);
                    leaf
                }
                None => defaults[0],
            };
            for level in (0..256).rev() {
                let sibling = siblings[level];
                let (left, right) = if bit_at(key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
                let parent = internal_hash(&left, &right);
                let content = [left.as_slice(), right.as_slice()].concat();
                if let Some(batch) = batch.as_deref_mut() {
                    batch.put_cf(self.cf(CF_MERKLE), parent, &content);
                }
                overrides.insert(parent, content);
                current = parent;
            }
            root = current;
        }

        if let Some(batch) = batch.as_deref_mut() {
            if !changes.is_empty() {
                batch.put_cf(self.cf(CF_META), MERKLE_ROOT_KEY, root);
            }
        }
        Ok(root)
    }

    /// Get the account state from the DB
    pub fn get_account(&self, address: &Address) -> Result<Option<AccountEntry>, StorageError> {
        KvRead::get(self, &AccountKey(address))
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

    /// Highest height with a finality certificate, if any.
    ///
    /// Found by seeking backwards over the `meta:finality:` prefix rather than
    /// maintaining a separate counter — the keys are zero-padded to 20 digits
    /// so lexicographic order is numeric order, and this is the same reverse-seek
    /// pattern `get_validator_set_at` already uses. A counter would be one more
    /// thing that can drift out of step with the records it summarises.
    ///
    /// Certificates are written as quorums complete, which is not necessarily in
    /// height order, so this is the highest *certified* height and not
    /// automatically a watermark below which everything is final. Callers that
    /// need a contiguous guarantee should check the heights they care about.
    pub fn get_finalized_height(&self) -> Result<Option<u64>, StorageError> {
        let prefix = b"meta:finality:";
        // u64::MAX zero-padded: seeks past every real key, so Reverse starts at
        // the highest one that exists.
        let seek_key = format!("meta:finality:{:020}", u64::MAX);
        let iter = self.db.iterator_cf(
            self.cf(CF_META),
            IteratorMode::From(seek_key.as_bytes(), Direction::Reverse),
        );
        for item in iter {
            let (key, _value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let digits = &key[prefix.len()..];
            let height = std::str::from_utf8(digits)
                .ok()
                .and_then(|d| d.parse::<u64>().ok())
                .ok_or(StorageError::CorruptedMeta)?;
            return Ok(Some(height));
        }
        Ok(None)
    }

    /// Every persisted precommit vote at heights >= `cutoff` — used by
    /// `spawn_finality` on startup to reconstruct its in-memory tallies from
    /// whatever survived a restart, since keys are zero-padded so this seek
    /// lands exactly at `cutoff` and reads forward.
    pub fn get_precommit_votes_from(&self, cutoff: u64) -> Result<Vec<PrecommitVoteRecord>, StorageError> {
        let prefix = b"meta:precommit:";
        let seek_key = format!("meta:precommit:{cutoff:020}");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(seek_key.as_bytes(), Direction::Forward));
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (record, _len): (PrecommitVoteRecord, usize) = bincode::serde::decode_from_slice(&value, config)?;
            results.push(record);
        }
        Ok(results)
    }

    /// Deletes every persisted precommit vote at `height` — called once that
    /// height finalizes (superseded by its `FinalityRecord`) or ages out of
    /// `TALLY_RETENTION_HEIGHTS`, so the DB never accumulates more than
    /// memory already bounds.
    pub fn delete_precommit_votes(&self, height: u64) -> Result<(), StorageError> {
        let prefix = format!("meta:precommit:{height:020}:");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        let mut batch = WriteBatch::default();
        for item in iter {
            let (key, _value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            batch.delete_cf(self.cf(CF_META), key);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Every persisted round-timeout vote at heights >= `cutoff` — mirrors
    /// `get_precommit_votes_from`, used by the same kind of restart-recovery
    /// reload for round-timeout tallying.
    pub fn get_round_timeout_votes_from(&self, cutoff: u64) -> Result<Vec<RoundTimeoutVoteRecord>, StorageError> {
        let prefix = b"meta:roundtimeout:";
        let seek_key = format!("meta:roundtimeout:{cutoff:020}");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(seek_key.as_bytes(), Direction::Forward));
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (record, _len): (RoundTimeoutVoteRecord, usize) =
                bincode::serde::decode_from_slice(&value, config)?;
            results.push(record);
        }
        Ok(results)
    }

    /// Deletes every persisted round-timeout vote at `height, round` — called
    /// once that round is certified (superseded by its `RoundCertificate`) or
    /// ages out of `TALLY_RETENTION_HEIGHTS`. Mirrors `delete_precommit_votes`.
    pub fn delete_round_timeout_votes(&self, height: u64, round: u32) -> Result<(), StorageError> {
        let prefix = format!("meta:roundtimeout:{height:020}:{round}:");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        let mut batch = WriteBatch::default();
        for item in iter {
            let (key, _value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            batch.delete_cf(self.cf(CF_META), key);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// One voter's persisted dissent at `height`, if any — used to enforce
    /// one dissent per (height, voter).
    pub fn get_dissent(&self, height: u64, voter: &Address) -> Result<Option<DissentRecord>, StorageError> {
        let key = format!("meta:dissent:{height:020}:{voter}");
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Every persisted dissent at heights >= `cutoff` — mirrors
    /// `get_precommit_votes_from`, used by `spawn_finality` on startup.
    pub fn get_dissents_from(&self, cutoff: u64) -> Result<Vec<DissentRecord>, StorageError> {
        let prefix = b"meta:dissent:";
        let seek_key = format!("meta:dissent:{cutoff:020}");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(seek_key.as_bytes(), Direction::Forward));
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let config = bincode::config::standard();
            let (record, _len): (DissentRecord, usize) = bincode::serde::decode_from_slice(&value, config)?;
            results.push(record);
        }
        Ok(results)
    }

    /// Deletes every persisted dissent at `height` — mirrors
    /// `delete_precommit_votes`, called once `height` ages out of
    /// `TALLY_RETENTION_HEIGHTS`.
    pub fn delete_dissents(&self, height: u64) -> Result<(), StorageError> {
        let prefix = format!("meta:dissent:{height:020}:");
        let iter = self
            .db
            .iterator_cf(self.cf(CF_META), IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        let mut batch = WriteBatch::default();
        for item in iter {
            let (key, _value) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            batch.delete_cf(self.cf(CF_META), key);
        }
        self.db.write(batch)?;
        Ok(())
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
        KvRead::get(self, &StakeKey { master, validator })
    }

    /// Masters currently staking to `validator`. One-master-per-validator is
    /// an enforced invariant, not just an assumption — callers should treat
    /// a `len() > 1` result as a bug, not a valid multi-delegator state.
    pub fn get_stakes_by_validator(&self, validator: &Address) -> Result<Vec<Address>, StorageError> {
        Ok(KvRead::get(self, &StakeByValidatorKey(validator))?.unwrap_or_default())
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
            let key = AccountKey(address).encode();
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
                StakeKey { master: address, validator: address }.encode(),
                bincode::serde::encode_to_vec(&allocation, config)?,
            ));
            entries.push((
                StakeByValidatorKey(address).encode(),
                bincode::serde::encode_to_vec(&vec![address.clone()], config)?,
            ));

            // The other half of the same fix: `apply_stake` always moves the
            // staked amount into `stake_subaccount(validator)`'s real
            // balance, so every allocation it creates is backed by funds a
            // slash/unbond can actually debit. The synthesized allocation
            // above skipped that, leaving the sub-account at its default
            // zero balance — `circuit_staking::apply_slash` would then
            // underflow subtracting from it (hit for real via downtime
            // slashing, which is the first path that reaches a genesis-only
            // validator without needing submitted evidence). Fund it here so
            // genesis produces the same invariant `apply_stake` would:
            // sub-account balance >= sum of active allocations against it.
            let sub_account = stake_subaccount(address);
            let mut sub_entry = self
                .accounts
                .get(&sub_account)
                .cloned()
                .unwrap_or(AccountEntry { balance: 0, nonce: 0, identity_hash: None, zk_identity_verified: false, attested_by: None });
            sub_entry.balance += validator.stake;
            entries.push((
                AccountKey(&sub_account).encode(),
                bincode::serde::encode_to_vec(&sub_entry, config)?,
            ));
        }
        let mut genesis_validators: Vec<Address> = self.validators.keys().cloned().collect();
        genesis_validators.sort();
        entries.push((
            b"validator_set:00000000000000000000".to_vec(),
            bincode::serde::encode_to_vec(&genesis_validators, config)?,
        ));
        if let Some(attestor) = &self.attestor {
            // Seeds the multi-attestor registry with this chain-spec's
            // legacy single attestor field, so a spec written before the
            // Trust Spectrum registry existed still grants a working
            // attestor at genesis instead of silently having none.
            let record = AttestorRecord { name: "genesis".to_string(), registered_at: self.height };
            entries.push((
                AttestorRecordKey(attestor).encode(),
                bincode::serde::encode_to_vec(&record, config)?,
            ));
        }
        if let Some(governor) = &self.governor {
            entries.push((GovernorKey.encode(), bincode::serde::encode_to_vec(governor, config)?));
        }
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
///
/// `effective_height` is the height this key becomes valid *from* — a
/// `RegisterBlsKey` action executed in block `H` takes effect at `H + 1`,
/// same one-block delay as `ValidatorSetSnapshot`, so a block never observes
/// a key change caused by its own actions. Genesis registrations use `0`.
/// Written alongside the plain current-key record so `get_bls_pubkey_at` can
/// recover which key was valid at any past height even after a rotation.
#[derive(Debug)]
pub struct BlsKeyRegistration {
    pub address: Address,
    pub pubkey: BlsPublicKey,
    pub effective_height: u64,
}

impl BatchWritable for BlsKeyRegistration {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(&self.pubkey, config)?;
        let current_key = BlsKeyKey(&self.address).encode();
        let history_key =
            format!("meta:blskey_hist:{}:{:020}", self.address, self.effective_height).into_bytes();
        Ok(vec![(current_key, value.clone()), (history_key, value)])
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

/// One validator's persisted precommit vote for `height`/`block_hash`, so a
/// restart before quorum is reached doesn't lose a tally `arxd/finality`
/// already gossiped and verified. Deleted once its height finalizes
/// (superseded by `FinalityRecord`) or ages out of `TALLY_RETENTION_HEIGHTS`,
/// mirroring the in-memory tally's own lifetime exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecommitVoteRecord {
    pub height: u64,
    pub block_hash: String,
    pub voter: Address,
    pub signature: BlsSignature,
    pub ep: [u8; 32],
}

impl BatchWritable for PrecommitVoteRecord {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:precommit:{:020}:{}:{}", self.height, self.block_hash, self.voter).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One validator's persisted dissent for `height` — mirrors
/// `PrecommitVoteRecord` exactly, including the `TALLY_RETENTION_HEIGHTS`
/// pruning schedule; see `arxd_finality::Dissent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissentRecord {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub ep: [u8; 32],
    pub reason: String,
    pub voter: Address,
    pub signature: BlsSignature,
    /// `sha256(signing_bytes_for(disputed block's header))` — binds this
    /// dissent to the exact block it disagrees with, since `block_hash` is
    /// an opaque chain-internal hash a verifier holding only this record
    /// cannot recompute. See `arxd_finality::Dissent::header_commitment`.
    pub header_commitment: [u8; 32],
}

impl BatchWritable for DissentRecord {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:dissent:{:020}:{}", self.height, self.voter).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

impl BatchWritable for FinalityRecord {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:finality:{:020}", self.height).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

// The type itself now lives in `xc_primitives` (so `Block::round_certificate`
// can carry it — `core/primitives` can't depend on `core/storage`). Re-
// exported under its old name here so existing `use xc_storage::
// RoundCertificate` call sites (`arxd/finality`) don't need to change.
pub use xc_primitives::RoundCertificate;

impl BatchWritable for RoundCertificate {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key = format!("meta:roundcert:{:020}:{}", self.height, self.round).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One validator's persisted vote that `round` at `height` timed out —
/// mirrors `PrecommitVoteRecord` exactly, including the
/// `TALLY_RETENTION_HEIGHTS`-driven pruning; see
/// `arxd_finality::RoundTimeoutVote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundTimeoutVoteRecord {
    pub height: u64,
    pub round: u32,
    pub voter: Address,
    pub signature: BlsSignature,
}

impl BatchWritable for RoundTimeoutVoteRecord {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let key =
            format!("meta:roundtimeout:{:020}:{}:{}", self.height, self.round, self.voter).into_bytes();
        let config = bincode::config::standard();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// A set of account changes to be written atomically. Not account-circuit
/// business logic — just the write-batch shape any circuit that touches
/// accounts (`circuit-account`, `circuit-rwa-asset`, ...) hands back.
#[derive(Debug, Default)]
pub struct AccountUpdates(pub BTreeMap<Address, AccountEntry>);

impl BatchWritable for AccountUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (address, entry) in &self.0 {
            let key = AccountKey(address).encode();
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
                let key = StakeKey { master, validator }.encode();
                let value = bincode::serde::encode_to_vec(allocation, config)?;
                entries.push((key, value));
            }
        }
        for (validator, masters) in &self.validator_index {
            if !masters.is_empty() {
                let key = StakeByValidatorKey(validator).encode();
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
                deletes.push(StakeKey { master, validator }.encode());
            }
        }
        for (validator, masters) in &self.validator_index {
            if masters.is_empty() {
                deletes.push(StakeByValidatorKey(validator).encode());
            }
        }
        Ok(deletes)
    }
}

/// A set of asset-balance changes to be written atomically alongside a
/// block, same reasoning as `AccountUpdates` — mint (`RegisterAsset`'s
/// `IssueAsset`) and compliance-gated transfer both produce one of these
/// rather than touching `AccountUpdates`, which is what keeps regulated
/// asset balances out of the native token balance.
#[derive(Debug, Default)]
pub struct AssetBalanceUpdates(pub BTreeMap<(String, Address), u128>);

impl BatchWritable for AssetBalanceUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for ((asset_id, owner), balance) in &self.0 {
            let key = AssetBalanceKey { asset_id, owner }.encode();
            let value = bincode::serde::encode_to_vec(balance, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

/// The non-consensus index rows that make asset state readable by wallet:
/// the registry list behind `GET /assets`, and one list per owner behind
/// `GET /accounts/{address}/assets`.
///
/// Both live in `CF_META`, which `is_state_key` excludes, so writing them
/// leaves the state root untouched — a node that somehow lost these rows
/// would serve worse listings but would still agree on consensus. That is
/// the whole reason this is an index rather than a re-keying of
/// `AssetBalanceKey`, whose keys are merkleized.
///
/// Only changed rows are present; a block with no asset activity produces an
/// empty value here and writes nothing.
#[derive(Debug, Default)]
pub struct AssetIndexUpdates {
    /// The full new registered-asset-id list, when a `RegisterAsset` in this
    /// block added to it.
    pub registry: Option<Vec<String>>,
    /// `owner -> full new list of asset ids held`.
    pub owners: BTreeMap<Address, Vec<String>>,
}

impl AssetIndexUpdates {
    /// Whether anything would be written. Lets a caller skip pushing this
    /// into the batch at all on the common no-asset-activity block.
    pub fn is_empty(&self) -> bool {
        self.registry.is_none() && self.owners.is_empty()
    }
}

impl BatchWritable for AssetIndexUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        if let Some(ids) = &self.registry {
            let value = bincode::serde::encode_to_vec(ids, config)?;
            entries.push((AssetIndexKey.encode(), value));
        }
        for (owner, asset_ids) in &self.owners {
            let value = bincode::serde::encode_to_vec(asset_ids, config)?;
            entries.push((AccountAssetsKey(owner).encode(), value));
        }
        Ok(entries)
    }
}

impl BatchWritable for Asset {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let key = AssetKey(&self.asset_id).encode();
        let value = bincode::serde::encode_to_vec(self, config)?;
        Ok(vec![(key, value)])
    }
}

/// One `RegisterAttestor` write — a single `CF_ATTESTORS` record, merkleized
/// via `is_state_key` (unlike `Asset`'s `CF_META` registry row).
#[derive(Debug)]
pub struct AttestorRegistration {
    pub attestor: Address,
    pub record: AttestorRecord,
}

impl BatchWritable for AttestorRegistration {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let key = AttestorRecordKey(&self.attestor).encode();
        let value = bincode::serde::encode_to_vec(&self.record, config)?;
        Ok(vec![(key, value)])
    }
}

/// One `DeregisterAttestor` write — physically removes the `CF_ATTESTORS`
/// record rather than flagging it inactive, same as any other merkleized
/// state key; deletions are already routed through the state root via
/// `batch_deletes`.
#[derive(Debug)]
pub struct AttestorDeregistration(pub Address);

impl BatchWritable for AttestorDeregistration {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(Vec::new())
    }

    fn batch_deletes(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(vec![AttestorRecordKey(&self.0).encode()])
    }
}

/// Read view for in-progress block execution: checks not-yet-committed
/// updates from earlier actions in the same block before falling through to
/// `db`. Lets circuits (`circuits/staking`, `circuits/account`, ...) see a
/// single `&dyn KvRead` regardless of whether a key was just written this
/// block or needs to come from disk, replacing what used to be several
/// hand-rolled "check the overlay map, else hit the db" closures per key
/// namespace.
pub struct BlockView<'a> {
    db: &'a ArxiumDb,
    entries: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> BlockView<'a> {
    pub fn new(db: &'a ArxiumDb) -> Self {
        Self { db, entries: HashMap::new() }
    }

    pub fn put<K: KeySpec>(&mut self, key: &K, value: &K::Value) -> Result<(), StorageError> {
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
        self.entries.insert(key.encode(), Some(bytes));
        Ok(())
    }

    pub fn delete<K: KeySpec>(&mut self, key: &K) {
        self.entries.insert(key.encode(), None);
    }

    /// Folds a batch of account changes into the view — every entry is an
    /// upsert, accounts are never deleted.
    pub fn apply_accounts(&mut self, updates: &AccountUpdates) -> Result<(), StorageError> {
        for (address, entry) in &updates.0 {
            self.put(&AccountKey(address), entry)?;
        }
        Ok(())
    }

    /// Folds a batch of stake changes into the view — `None`/empty entries
    /// (see `StakeUpdates` docs) become deletes, same rule `batch_entries`/
    /// `batch_deletes` use for the on-disk write.
    pub fn apply_stakes(&mut self, updates: &StakeUpdates) -> Result<(), StorageError> {
        for ((master, validator), allocation) in &updates.allocations {
            match allocation {
                Some(allocation) => self.put(&StakeKey { master, validator }, allocation)?,
                None => self.delete(&StakeKey { master, validator }),
            }
        }
        for (validator, masters) in &updates.validator_index {
            if masters.is_empty() {
                self.delete(&StakeByValidatorKey(validator));
            } else {
                self.put(&StakeByValidatorKey(validator), masters)?;
            }
        }
        Ok(())
    }

    /// Folds a batch of asset-balance changes into the view — every entry is
    /// an upsert, mirroring `apply_accounts` (balances go to 0, never get
    /// deleted as a row).
    pub fn apply_asset_balances(&mut self, updates: &AssetBalanceUpdates) -> Result<(), StorageError> {
        for ((asset_id, owner), balance) in &updates.0 {
            self.put(&AssetBalanceKey { asset_id, owner }, balance)?;
        }
        Ok(())
    }

    /// Folds a `RegisterAttestor` write into the view — see `put`/`delete`
    /// above, used directly (not a `KeySpec` bulk struct like
    /// `apply_asset_balances`) since a block registers/deregisters at most
    /// one attestor per action.
    pub fn apply_attestor_registration(&mut self, registration: &AttestorRegistration) -> Result<(), StorageError> {
        self.put(&AttestorRecordKey(&registration.attestor), &registration.record)
    }

    /// Folds a `DeregisterAttestor` write into the view.
    pub fn apply_attestor_deregistration(&mut self, deregistration: &AttestorDeregistration) {
        self.delete(&AttestorRecordKey(&deregistration.0))
    }
}

impl KvRead for BlockView<'_> {
    type Error = StorageError;

    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, StorageError> {
        match self.entries.get(&key.encode()) {
            Some(None) => Ok(None),
            Some(Some(bytes)) => {
                let config = bincode::config::standard();
                let (value, _len) = bincode::serde::decode_from_slice(bytes, config)?;
                Ok(Some(value))
            }
            None => KvRead::get(self.db, key),
        }
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
            tx_root: [0u8; 32],
            proposer: None,
            signature: None,
            state_root: String::new(),
            round: 0,
            round_certificate: None,
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
        validators.insert(addr(1), xc_primitives::ValidatorEntry { stake: 1_000_000, bls_pubkey: None });
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts: Default::default(),
            validators,
            boot_nodes: vec![],
            attestor: None,
            governor: None,
        })
        .unwrap();

        let allocation = db.get_stake_allocation(&addr(1), &addr(1)).unwrap().unwrap();
        assert_eq!(allocation.active_amount, 1_000_000);
        assert_eq!(db.get_stakes_by_validator(&addr(1)).unwrap(), vec![addr(1)]);

        // The allocation alone isn't enough — `apply_slash` debits real
        // balance out of `stake_subaccount(validator)`, not the allocation
        // record. Without this, a slash against a genesis-only validator
        // underflows a balance that was never funded (previously masked by
        // a `saturating_sub` band-aid rather than fixed at the source).
        let sub_account = xc_primitives::stake_subaccount(&addr(1));
        let sub_entry = db.get_account(&sub_account).unwrap().unwrap();
        assert_eq!(sub_entry.balance, 1_000_000);
    }

    /// Two genesis validators must each get their own funded sub-account,
    /// not share one balance or overwrite each other's — sub-accounts are
    /// keyed by a domain-separated hash of the validator address, so this
    /// also guards against an indexing mistake that happened to work for a
    /// single validator.
    #[test]
    fn multiple_genesis_validators_each_get_a_distinct_funded_subaccount() {
        let db = temp_db();
        let mut validators = std::collections::BTreeMap::new();
        validators.insert(addr(1), xc_primitives::ValidatorEntry { stake: 1_000_000, bls_pubkey: None });
        validators.insert(addr(2), xc_primitives::ValidatorEntry { stake: 2_000_000, bls_pubkey: None });
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts: Default::default(),
            validators,
            boot_nodes: vec![],
            attestor: None,
            governor: None,
        })
        .unwrap();

        let sub1 = xc_primitives::stake_subaccount(&addr(1));
        let sub2 = xc_primitives::stake_subaccount(&addr(2));
        assert_ne!(sub1, sub2);
        assert_eq!(db.get_account(&sub1).unwrap().unwrap().balance, 1_000_000);
        assert_eq!(db.get_account(&sub2).unwrap().unwrap().balance, 2_000_000);
    }

    /// The checkpoint output must be a standalone, independently-openable
    /// `ArxiumDb` holding exactly what was committed at checkpoint time — the
    /// entire point of `export_checkpoint` is that a new node can use it as
    /// its data dir in place of replaying from genesis.
    #[test]
    fn exported_checkpoint_reopens_with_identical_data() {
        let db = temp_db();
        db.write_batch(&block(0, vec![])).unwrap();
        db.write_batch(&block(1, vec![])).unwrap();
        let mut validators = std::collections::BTreeMap::new();
        validators.insert(addr(1), xc_primitives::ValidatorEntry { stake: 500, bls_pubkey: None });
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts: Default::default(),
            validators,
            boot_nodes: vec![],
            attestor: None,
            governor: None,
        })
        .unwrap();

        let checkpoint_path = std::env::temp_dir().join(format!("arxium-test-checkpoint-{}", uuid_like()));
        db.export_checkpoint(&checkpoint_path).unwrap();

        let reopened = ArxiumDb::open(&checkpoint_path).unwrap();
        assert_eq!(reopened.get_tip_height().unwrap(), Some(1));
        assert_eq!(reopened.get_block::<()>(0).unwrap().unwrap().height, 0);
        assert_eq!(
            reopened.get_stake_allocation(&addr(1), &addr(1)).unwrap().unwrap().active_amount,
            500
        );

        // The two are independent copies from this point on — writing to one
        // must not affect the other.
        db.write_batch(&block(2, vec![])).unwrap();
        assert_eq!(reopened.get_tip_height().unwrap(), Some(1));
    }

    /// `export_checkpoint` refuses to overwrite an existing path — this
    /// mirrors RocksDB's own checkpoint semantics (it errors rather than
    /// merging into a directory that already has content) rather than
    /// silently corrupting or losing whatever was already there.
    #[test]
    fn export_checkpoint_fails_if_the_destination_already_exists() {
        let db = temp_db();
        db.write_batch(&block(0, vec![])).unwrap();

        let checkpoint_path = std::env::temp_dir().join(format!("arxium-test-checkpoint-{}", uuid_like()));
        db.export_checkpoint(&checkpoint_path).unwrap();

        assert!(db.export_checkpoint(&checkpoint_path).is_err());
    }
}

#[cfg(test)]
mod asset_index_tests {
    use super::*;

    /// A counter, not just a timestamp: `cargo test` runs these in parallel
    /// threads of one process, and macOS clock granularity is coarse enough
    /// that two of them read the same nanosecond, collide on a path, and fail
    /// on RocksDB's LOCK file. Same reason `explorer_index_tests::uuid_like`
    /// mixes in an atomic.
    fn temp_db() -> ArxiumDb {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "arxium-test-asset-index-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ArxiumDb::open(&path).unwrap()
    }

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn asset(id: &str, issuer: &Address, gated: bool) -> Asset {
        Asset {
            asset_id: id.to_string(),
            issuer: issuer.clone(),
            compliance_required: gated,
        }
    }

    fn balances(rows: &[(&str, &Address, u128)]) -> AssetBalanceUpdates {
        AssetBalanceUpdates(
            rows.iter()
                .map(|(id, owner, amount)| ((id.to_string(), (*owner).clone()), *amount))
                .collect(),
        )
    }

    /// The whole point of the index: a wallet asks "what does this account
    /// hold" and gets an answer without reading every balance on the chain.
    #[test]
    fn registering_and_issuing_makes_an_asset_listable_and_findable_by_owner() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let gold = asset("gold", &issuer, true);

        let updates = balances(&[("gold", &holder, 1_000)]);
        let index = db.asset_index_updates(&[gold.clone()], &updates).unwrap();
        db.write_batches(&[&gold, &updates, &index]).unwrap();

        assert_eq!(db.list_asset_ids().unwrap(), vec!["gold".to_string()]);
        let listed = db.list_assets().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].asset_id, "gold");
        assert!(listed[0].compliance_required);

        assert_eq!(
            db.get_account_assets(&holder).unwrap(),
            vec!["gold".to_string()]
        );
        assert_eq!(db.get_asset_balance("gold", &holder).unwrap(), 1_000);
        // An account that has never held anything gets an empty list, not an
        // error and not someone else's.
        assert!(db.get_account_assets(&addr(9)).unwrap().is_empty());
    }

    /// A second block must extend both lists rather than replace them —
    /// `asset_index_updates` reads the current value and hands back the full
    /// new one, so a bug here silently drops the earlier holdings.
    #[test]
    fn a_later_block_extends_the_lists_instead_of_overwriting_them() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);

        let gold = asset("gold", &issuer, true);
        let first = balances(&[("gold", &holder, 1_000)]);
        let index = db.asset_index_updates(&[gold.clone()], &first).unwrap();
        db.write_batches(&[&gold, &first, &index]).unwrap();

        let silver = asset("silver", &issuer, false);
        let second = balances(&[("silver", &holder, 50)]);
        let index = db.asset_index_updates(&[silver.clone()], &second).unwrap();
        db.write_batches(&[&silver, &second, &index]).unwrap();

        assert_eq!(
            db.list_asset_ids().unwrap(),
            vec!["gold".to_string(), "silver".to_string()]
        );
        assert_eq!(
            db.get_account_assets(&holder).unwrap(),
            vec!["gold".to_string(), "silver".to_string()]
        );
    }

    /// Re-touching the same (asset, owner) pair must not grow the list — a
    /// wallet would otherwise show the same holding once per transfer ever
    /// made.
    #[test]
    fn repeated_activity_on_one_holding_does_not_duplicate_it() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let gold = asset("gold", &issuer, true);

        for amount in [1_000u128, 900, 800] {
            let updates = balances(&[("gold", &holder, amount)]);
            let index = db.asset_index_updates(&[], &updates).unwrap();
            db.write_batches(&[&gold, &updates, &index]).unwrap();
        }

        assert_eq!(
            db.get_account_assets(&holder).unwrap(),
            vec!["gold".to_string()]
        );
    }

    /// A block with no asset activity must write nothing, so the common case
    /// costs one map lookup rather than a batch entry.
    #[test]
    fn a_block_with_no_asset_activity_produces_no_index_rows() {
        let db = temp_db();
        let index = db
            .asset_index_updates(&[], &AssetBalanceUpdates::default())
            .unwrap();
        assert!(index.is_empty());
        assert!(index.batch_entries().unwrap().is_empty());
    }

    /// Both sides of a transfer are indexed, not just the sender — the
    /// recipient is the account that most needs to discover it now holds
    /// something.
    #[test]
    fn a_transfer_indexes_the_recipient_too() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(3);
        let gold = asset("gold", &issuer, true);

        let updates = balances(&[("gold", &issuer, 900), ("gold", &recipient, 100)]);
        let index = db.asset_index_updates(&[gold.clone()], &updates).unwrap();
        db.write_batches(&[&gold, &updates, &index]).unwrap();

        assert_eq!(
            db.get_account_assets(&issuer).unwrap(),
            vec!["gold".to_string()]
        );
        assert_eq!(
            db.get_account_assets(&recipient).unwrap(),
            vec!["gold".to_string()]
        );
    }

    /// The index lives in `CF_META`, which `is_state_key` excludes. If it ever
    /// started counting toward the merkle root, two nodes that indexed
    /// differently would disagree on state and the chain would halt.
    #[test]
    fn index_rows_are_not_consensus_state() {
        let holder = addr(2);
        let index = AssetIndexUpdates {
            registry: Some(vec!["gold".to_string()]),
            owners: [(holder, vec!["gold".to_string()])].into_iter().collect(),
        };
        for (key, _) in index.batch_entries().unwrap() {
            assert!(
                !is_state_key(&key),
                "index key {} must stay out of the state root",
                String::from_utf8_lossy(&key)
            );
            assert_eq!(cf_for_key(&key), CF_META);
        }
    }
}

#[cfg(test)]
mod schema_version_tests {
    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "arxium-test-schema-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// A fresh database has no marker yet; `open` must stamp it rather than
    /// error, and a second open of the same path must then see it agree.
    #[test]
    fn opening_a_fresh_db_stamps_the_current_schema_version() {
        let path = temp_path();
        {
            let db = ArxiumDb::open(&path).unwrap();
            let stamped = db.db.get_cf(db.cf(CF_META), SCHEMA_VERSION_KEY).unwrap().unwrap();
            assert_eq!(u32::from_le_bytes(stamped.try_into().unwrap()), SCHEMA_VERSION);
        }
        assert!(ArxiumDb::open(&path).is_ok());
    }

    /// A database stamped by a newer binary must not silently open under an
    /// older one — that's the whole point of the marker (`Arxium_OpenItems.md`
    /// §7's migration-mechanism prerequisite).
    #[test]
    fn opening_a_db_stamped_by_a_newer_binary_is_refused() {
        let path = temp_path();
        {
            let db = ArxiumDb::open(&path).unwrap();
            db.db
                .put_cf(db.cf(CF_META), SCHEMA_VERSION_KEY, (SCHEMA_VERSION + 1).to_le_bytes())
                .unwrap();
        }
        match ArxiumDb::open(&path) {
            Err(err) => assert!(matches!(err, StorageError::SchemaTooNew { .. }), "got {err:?}"),
            Ok(_) => panic!("expected SchemaTooNew"),
        }
    }
}

#[cfg(test)]
mod round_certificate_tests {
    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "arxium-test-roundcert-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn sig(n: u8) -> BlsSignature {
        BlsSignature([n; 96])
    }

    /// A height with no persisted `RoundCertificate` is round 0 — the
    /// primary is eligible until a quorum certifies otherwise.
    #[test]
    fn current_round_with_no_certificates_is_zero() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        assert_eq!(db.current_round(5).unwrap(), 0);
    }

    /// `current_round` is one past the highest certified round for that
    /// height — a certificate for round 0 makes round 1 eligible, and a
    /// gap (round 2 certified without round 1) still reports the highest
    /// seen plus one, since eligibility only ever moves forward.
    #[test]
    fn current_round_is_one_past_the_highest_certificate_for_that_height() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batches(&[&RoundCertificate {
            height: 5,
            round: 0,
            signers: vec![addr(1)],
            aggregate_signature: sig(1),
        }])
        .unwrap();
        assert_eq!(db.current_round(5).unwrap(), 1);

        db.write_batches(&[&RoundCertificate {
            height: 5,
            round: 2,
            signers: vec![addr(1), addr(2)],
            aggregate_signature: sig(2),
        }])
        .unwrap();
        assert_eq!(db.current_round(5).unwrap(), 3);

        // A different height's certificates must not leak into this one.
        assert_eq!(db.current_round(6).unwrap(), 0);
    }

    #[test]
    fn round_certificate_round_trips_through_storage() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        let record = RoundCertificate {
            height: 9,
            round: 1,
            signers: vec![addr(3), addr(4)],
            aggregate_signature: sig(7),
        };
        db.write_batches(&[&record]).unwrap();

        let fetched = db.get_round_certificate(9, 1).unwrap().expect("certificate should be persisted");
        assert_eq!(fetched.height, 9);
        assert_eq!(fetched.round, 1);
        assert_eq!(fetched.signers, vec![addr(3), addr(4)]);
        assert!(db.get_round_certificate(9, 0).unwrap().is_none());
    }

    /// Round-timeout votes are readable by `get_round_timeout_votes_from`
    /// and, once a round is certified, `delete_round_timeout_votes` removes
    /// exactly that height/round's votes and no others.
    #[test]
    fn round_timeout_votes_are_listed_and_pruned_per_round() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batches(&[
            &RoundTimeoutVoteRecord { height: 10, round: 0, voter: addr(1), signature: sig(1) },
            &RoundTimeoutVoteRecord { height: 10, round: 1, voter: addr(1), signature: sig(2) },
            &RoundTimeoutVoteRecord { height: 11, round: 0, voter: addr(1), signature: sig(3) },
        ])
        .unwrap();

        assert_eq!(db.get_round_timeout_votes_from(0).unwrap().len(), 3);

        db.delete_round_timeout_votes(10, 0).unwrap();

        let remaining = db.get_round_timeout_votes_from(0).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|r| !(r.height == 10 && r.round == 0)));
    }
}

#[cfg(test)]
mod bls_key_history_tests {
    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "arxium-test-blskeyhist-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn pubkey(n: u8) -> BlsPublicKey {
        BlsPublicKey([n; 48])
    }

    /// A validator signs at height 5 under key A, then rotates to key B
    /// (effective at height 11). A node syncing from a fresh DB must still
    /// verify the height-5 artifact against key A — `get_bls_pubkey_at(5)`
    /// must return the pre-rotation key, not whatever `get_bls_pubkey`
    /// (current) now reports. This is the exact scenario the B1c-follow-up
    /// gap allowed: `get_bls_pubkey` alone would return key B for a height-5
    /// lookup post-rotation, making replay verification signer-history
    /// dependent instead of deterministic.
    #[test]
    fn replaying_a_pre_rotation_height_from_a_fresh_db_still_resolves_the_old_key() {
        let path = temp_path();
        let validator = addr(1);
        let key_a = pubkey(0xAA);
        let key_b = pubkey(0xBB);

        {
            let db = ArxiumDb::open(&path).unwrap();
            db.write_batches(&[&BlsKeyRegistration { address: validator.clone(), pubkey: key_a.clone(), effective_height: 0 }])
                .unwrap();
            db.write_batches(&[&BlsKeyRegistration {
                address: validator.clone(),
                pubkey: key_b.clone(),
                effective_height: 11,
            }])
            .unwrap();
        }

        // Fresh open, as a syncing node would do — not reusing the handle
        // that wrote the rotation.
        let db = ArxiumDb::open(&path).unwrap();

        assert_eq!(db.get_bls_pubkey_at(&validator, 5).unwrap(), Some(key_a.clone()));
        assert_eq!(db.get_bls_pubkey_at(&validator, 10).unwrap(), Some(key_a));
        assert_eq!(db.get_bls_pubkey_at(&validator, 11).unwrap(), Some(key_b.clone()));
        assert_eq!(db.get_bls_pubkey_at(&validator, 100).unwrap(), Some(key_b.clone()));

        // The current-key lookup reflects only the latest rotation — using
        // it for a historical height would silently return the wrong key.
        assert_eq!(db.get_bls_pubkey(&validator).unwrap(), Some(key_b));
    }
}

/// `B3`: the incremental Merkle trie behind `compute_state_root`.
#[cfg(test)]
mod merkle_state_root_tests {
    use super::*;
    use xc_primitives::AccountEntry;

    fn temp_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "arxium-test-merkle-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn entry(balance: u128) -> AccountEntry {
        AccountEntry { balance, nonce: 0, identity_hash: None, zk_identity_verified: false, attested_by: None }
    }

    fn accounts(pairs: &[(u8, u128)]) -> AccountUpdates {
        AccountUpdates(pairs.iter().map(|(n, bal)| (addr(*n), entry(*bal))).collect())
    }

    /// An empty database's root is the canonical empty-trie hash, and asking
    /// twice gives the same answer without anything written.
    #[test]
    fn an_empty_db_has_a_stable_root() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        let root1 = db.compute_state_root(&[]).unwrap();
        let root2 = db.compute_state_root(&[]).unwrap();
        assert_eq!(root1, root2);
        assert_eq!(root1, format!("0x{}", hex::encode(default_hashes()[256])));
    }

    /// Speculating over an overlay never touches disk — the root the
    /// overlay predicts must match the root actually observed once the same
    /// overlay is committed for real.
    #[test]
    fn a_speculative_root_matches_the_root_after_actually_committing() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        let updates = accounts(&[(1, 100), (2, 200)]);
        let predicted = db.compute_state_root(&[&updates]).unwrap();

        db.write_batch(&updates).unwrap();
        let actual = db.compute_state_root(&[]).unwrap();
        assert_eq!(predicted, actual);
    }

    /// The whole point of `B3`: committing changes across several separate
    /// blocks (several `write_batch` calls) must land on exactly the same
    /// root as committing the same net state in one shot — the incremental
    /// walk can't be allowed to depend on how the writes were chunked.
    #[test]
    fn incremental_commits_match_one_combined_commit() {
        let incremental = ArxiumDb::open(&temp_path()).unwrap();
        incremental.write_batch(&accounts(&[(1, 100)])).unwrap();
        incremental.write_batch(&accounts(&[(2, 200)])).unwrap();
        incremental.write_batch(&accounts(&[(3, 300)])).unwrap();

        let combined = ArxiumDb::open(&temp_path()).unwrap();
        combined.write_batch(&accounts(&[(1, 100), (2, 200), (3, 300)])).unwrap();

        assert_eq!(incremental.compute_state_root(&[]).unwrap(), combined.compute_state_root(&[]).unwrap());
    }

    /// Overwriting an existing key changes the root, and re-overwriting it
    /// back to the original value returns the root to exactly what it was
    /// before — the trie has no memory of the detour.
    #[test]
    fn overwriting_and_reverting_a_value_round_trips_the_root() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batch(&accounts(&[(1, 100)])).unwrap();
        let original = db.compute_state_root(&[]).unwrap();

        db.write_batch(&accounts(&[(1, 999)])).unwrap();
        let changed = db.compute_state_root(&[]).unwrap();
        assert_ne!(original, changed);

        db.write_batch(&accounts(&[(1, 100)])).unwrap();
        assert_eq!(db.compute_state_root(&[]).unwrap(), original);
    }

    /// `prove` (Part 3 Stage 1) must produce a proof `xc_poe::state_trie::verify_proof`
    /// accepts against the exact root `compute_state_root` reports — a
    /// prover and verifier that quietly disagree on the trie's shape would
    /// make every downstream proof (bisection, a wallet's own balance) worth
    /// nothing.
    #[test]
    fn a_proof_of_an_existing_account_verifies_against_the_current_root() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batch(&accounts(&[(1, 100), (2, 200)])).unwrap();
        let root = db.compute_state_root(&[]).unwrap();
        let root_bytes = decode_root(&root).unwrap();

        let key = format!("account:{}", addr(1)).into_bytes();
        let proof = db.prove(&key, &root).unwrap();
        assert!(xc_poe::state_trie::verify_proof(root_bytes, &proof));
        assert_eq!(proof.value, Some(bincode::serde::encode_to_vec(entry(100), bincode::config::standard()).unwrap()));
    }

    /// A key that was never written proves as absent (non-inclusion) rather
    /// than erroring — the sparse trie has no separate "does this key exist"
    /// path, presence and absence are proved the same way.
    #[test]
    fn a_proof_of_a_never_written_key_is_non_inclusion() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batch(&accounts(&[(1, 100)])).unwrap();
        let root = db.compute_state_root(&[]).unwrap();
        let root_bytes = decode_root(&root).unwrap();

        let key = format!("account:{}", addr(9)).into_bytes();
        let proof = db.prove(&key, &root).unwrap();
        assert_eq!(proof.value, None);
        assert!(xc_poe::state_trie::verify_proof(root_bytes, &proof));
    }

    /// `prove` isn't limited to the current tip's root — `CF_MERKLE` nodes
    /// are content-addressed and never pruned, so a historical root a
    /// dispute references must still be provable against even after the
    /// trie has since moved on.
    #[test]
    fn a_historical_root_remains_provable_after_the_trie_moves_on() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        db.write_batch(&accounts(&[(1, 100)])).unwrap();
        let old_root = db.compute_state_root(&[]).unwrap();
        let old_root_bytes = decode_root(&old_root).unwrap();

        db.write_batch(&accounts(&[(1, 999), (2, 200)])).unwrap();
        assert_ne!(db.compute_state_root(&[]).unwrap(), old_root);

        let key = format!("account:{}", addr(1)).into_bytes();
        let proof = db.prove(&key, &old_root).unwrap();
        assert_eq!(proof.value, Some(bincode::serde::encode_to_vec(entry(100), bincode::config::standard()).unwrap()));
        assert!(xc_poe::state_trie::verify_proof(old_root_bytes, &proof));
    }

    /// Deleting a stake allocation back out of the trie must return the root
    /// to what it was before the key ever existed, not leave a tombstone
    /// behind that changes the hash.
    #[test]
    fn deleting_a_key_restores_the_prior_root() {
        let db = ArxiumDb::open(&temp_path()).unwrap();
        let before = db.compute_state_root(&[]).unwrap();

        let master = addr(1);
        let validator = addr(2);
        let allocation = xc_primitives::StakeAllocation {
            master: master.clone(),
            validator: validator.clone(),
            active_amount: 500,
            unbonding: None,
            created_at: 0,
            updated_at: 0,
        };
        db.write_batch(&StakeUpdates {
            allocations: BTreeMap::from([((master.clone(), validator.clone()), Some(allocation))]),
            validator_index: BTreeMap::from([(validator.clone(), vec![master.clone()])]),
        })
        .unwrap();
        assert_ne!(db.compute_state_root(&[]).unwrap(), before);

        db.write_batch(&StakeUpdates {
            allocations: BTreeMap::from([((master, validator.clone()), None)]),
            validator_index: BTreeMap::from([(validator, vec![])]),
        })
        .unwrap();
        assert_eq!(db.compute_state_root(&[]).unwrap(), before);
    }
}
