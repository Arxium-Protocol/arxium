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
use xc_primitives::{AccountEntry, Address, Asset, StakeAllocation};

pub const CF_META: &str = "meta";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_ASSETS: &str = "assets";

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

/// The registry record for a regulated asset — `issuer`/`compliance_required`,
/// not its balances (see `AssetBalanceKey`).
pub struct AssetKey<'a>(pub &'a str);
impl KeySpec for AssetKey<'_> {
    const CF: &'static str = CF_META;
    type Value = Asset;
    fn encode(&self) -> Vec<u8> {
        format!("meta:asset:{}", self.0).into_bytes()
    }
}

/// One account's balance of one asset. Lives in its own column family
/// (`CF_ASSETS`, included in `is_state_key`) so regulated-asset balances are
/// merkleized separately from the native token balance in `CF_ACCOUNTS`.
pub struct AssetBalanceKey<'a> {
    pub asset_id: &'a str,
    pub owner: &'a Address,
}
impl KeySpec for AssetBalanceKey<'_> {
    const CF: &'static str = CF_ASSETS;
    type Value = u128;
    fn encode(&self) -> Vec<u8> {
        format!("asset_balance:{}:{}", self.asset_id, self.owner).into_bytes()
    }
}

/// Every registered asset id, as one list.
///
/// A maintained index rather than a prefix scan over `meta:asset:`, for the
/// same reason `meta:operator_index:` exists: listing is a read path and the
/// codebase resolves column families by key *prefix* (`cf_for_key`), not by
/// `KeySpec::CF`. `meta:asset:{id}` is 11 bytes plus the id, so a 21-byte
/// asset id lands on the `key.len() == 32` arm and is filed under `CF_MERKLE`
/// instead of `CF_META`. It still round-trips — reads take the same arm — but
/// a scan of `CF_META` would silently skip exactly those assets. An index has
/// no such hole, and is a single read besides.
pub struct AssetIndexKey;
impl KeySpec for AssetIndexKey {
    const CF: &'static str = CF_META;
    type Value = Vec<String>;
    fn encode(&self) -> Vec<u8> {
        b"meta:asset_index".to_vec()
    }
}

/// Every asset id `owner` holds a balance row for.
///
/// The reverse of `AssetBalanceKey`, which is keyed `{asset_id}:{owner}` and
/// so can only be scanned by asset, never by owner. A wallet asks the
/// opposite question — "what does this account hold" — and answering it from
/// the balance keys alone would mean reading every balance on the chain.
///
/// Kept in `CF_META`, which `is_state_key` excludes, so maintaining it costs
/// nothing in the state root and cannot affect consensus. That is also why
/// this is an index and not a re-keying of `AssetBalanceKey`: those keys are
/// merkleized, and reordering them would change the state root.
pub struct AccountAssetsKey<'a>(pub &'a Address);
impl KeySpec for AccountAssetsKey<'_> {
    const CF: &'static str = CF_META;
    type Value = Vec<String>;
    fn encode(&self) -> Vec<u8> {
        format!("meta:account_assets:{}", self.0).into_bytes()
    }
}

/// The chain's sole attestor address (genesis-fixed, see `Snapshot::attestor`)
/// — the only sender `GrantAttestation`/`RevokeAttestation` accept.
pub struct AttestorKey;
impl KeySpec for AttestorKey {
    const CF: &'static str = CF_META;
    type Value = Address;
    fn encode(&self) -> Vec<u8> {
        b"meta:attestor".to_vec()
    }
}

/// Read-only view over typed keys. Never a write path: all writes stay
/// batched through `BatchWritable` in `core/storage`, applied atomically
/// once per block.
pub trait KvRead {
    type Error;
    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, Self::Error>;
}
