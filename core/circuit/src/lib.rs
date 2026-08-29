// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Typed storage keys for the namespaces circuits (and the
//! validator-identity logic next to them) actually touch, plus the
//! read-only trait `core/storage` implements over them.
//!
//! Circuits stay read-only against storage — they hand back typed update
//! structs (`AccountUpdates`, `StakeUpdates`, ...) that `core/storage`
//! writes atomically once per block. This crate exists so both sides agree
//! on key shape/column family without `core/storage` scattering
//! `format!("prefix:{}", ...)` calls a typo could silently desync.

use serde::Serialize;
use serde::de::DeserializeOwned;
use xc_bls::BlsPublicKey;
use xc_primitives::{AccountEntry, Address, StakeAllocation};

pub const CF_META: &str = "meta";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VALIDATORS: &str = "validators";

/// A typed storage key: which column family it lives in, what value it
/// decodes to, and how to encode itself to the raw bytes RocksDB stores.
pub trait KeySpec {
    const CF: &'static str;
    type Value: Serialize + DeserializeOwned;
    fn encode(&self) -> Vec<u8>;
}

pub struct AccountKey<'a>(pub &'a Address);
impl KeySpec for AccountKey<'_> {
    const CF: &'static str = CF_ACCOUNTS;
    type Value = AccountEntry;
    fn encode(&self) -> Vec<u8> {
        format!("account:{}", self.0).into_bytes()
    }
}

pub struct StakeKey<'a> {
    pub master: &'a Address,
    pub validator: &'a Address,
}
impl KeySpec for StakeKey<'_> {
    const CF: &'static str = CF_VALIDATORS;
    type Value = StakeAllocation;
    fn encode(&self) -> Vec<u8> {
        format!("stake:{}:{}", self.master, self.validator).into_bytes()
    }
}

pub struct StakeByValidatorKey<'a>(pub &'a Address);
impl KeySpec for StakeByValidatorKey<'_> {
    const CF: &'static str = CF_VALIDATORS;
    type Value = Vec<Address>;
    fn encode(&self) -> Vec<u8> {
        format!("stake_by_validator:{}", self.0).into_bytes()
    }
}

/// Shared between staking/validator-join logic and `arxd/finality` — not
/// exclusively "owned" by one circuit.
pub struct BlsKeyKey<'a>(pub &'a Address);
impl KeySpec for BlsKeyKey<'_> {
    const CF: &'static str = CF_META;
    type Value = BlsPublicKey;
    fn encode(&self) -> Vec<u8> {
        format!("meta:blskey:{}", self.0).into_bytes()
    }
}

/// Read-only view over typed keys. Never a write path: all writes stay
/// batched through `BatchWritable` in `core/storage`, applied atomically
/// once per block.
pub trait KvRead {
    type Error;
    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, Self::Error>;
}
