// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! [`BlockView`], the read-through overlay used while a block is executing.

use super::*;

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
    /// `Some` only in recording mode (`new_recording`) — every Merkleized
    /// key this view reads or writes gets logged here, so a caller building
    /// a fraud proof after the fact (see `arxd/node`'s `BlockDivergence`
    /// path) knows exactly which keys to fetch `ArxiumDb::prove` proofs
    /// for. `None` in the normal (block-production) path: no bookkeeping
    /// cost there at all, not even an empty-set allocation.
    touched: Option<RefCell<BTreeSet<Vec<u8>>>>,
}

impl<'a> BlockView<'a> {
    pub fn new(db: &'a ArxiumDb) -> Self {
        Self { db, entries: HashMap::new(), touched: None }
    }

    /// Same as `new`, but logs every Merkleized key touched via `get`/
    /// `put`/`delete` — see `touched_keys`. Non-Merkleized keys (`CF_META`,
    /// filtered by `is_state_key`) aren't logged: they have no trie proof
    /// to fetch, so recording them would just be noise for the caller.
    pub fn new_recording(db: &'a ArxiumDb) -> Self {
        Self { db, entries: HashMap::new(), touched: Some(RefCell::new(BTreeSet::new())) }
    }

    /// The Merkleized keys logged so far, in recording mode. Empty for a
    /// view built with `new`.
    pub fn touched_keys(&self) -> Vec<Vec<u8>> {
        match &self.touched {
            Some(touched) => touched.borrow().iter().cloned().collect(),
            None => Vec::new(),
        }
    }

    fn record_touched(&self, raw_key: &[u8]) {
        if let Some(touched) = &self.touched
            && is_state_key(raw_key) {
                touched.borrow_mut().insert(raw_key.to_vec());
            }
    }

    pub fn put<K: KeySpec>(&mut self, key: &K, value: &K::Value) -> Result<(), StorageError> {
        let raw_key = key.encode();
        self.record_touched(&raw_key);
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
        self.entries.insert(raw_key, Some(bytes));
        Ok(())
    }

    pub fn delete<K: KeySpec>(&mut self, key: &K) {
        let raw_key = key.encode();
        self.record_touched(&raw_key);
        self.entries.insert(raw_key, None);
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

    /// Folds a `RegisterAsset`/`IssueAsset` write into the view — see
    /// `apply_attestor_registration` below for why this goes through the
    /// view instead of a deferred `Vec`: without it, a same-block
    /// `RegisterAsset` followed by `IssueAsset` or a duplicate
    /// `RegisterAsset` reads stale (pre-block) state.
    pub fn apply_asset_registration(&mut self, asset: &Asset) -> Result<(), StorageError> {
        self.put(&AssetKey(&asset.asset_id), asset)
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
        let raw_key = key.encode();
        self.record_touched(&raw_key);
        match self.entries.get(&raw_key) {
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
