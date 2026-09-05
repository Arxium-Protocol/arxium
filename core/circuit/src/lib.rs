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
use xc_primitives::{AccountEntry, Address, Asset, AttestorRecord, StakeAllocation};

pub const CF_META: &str = "meta";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_ASSETS: &str = "assets";
pub const CF_ATTESTORS: &str = "attestors";
pub const CF_EVIDENCE: &str = "evidence";

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
/// not its balances (see `AssetBalanceKey`). Lives in `CF_ASSETS` (included in
/// `is_state_key`) so `compliance_required` is merkleized and provable to a
/// light client instead of sitting in `CF_META`.
pub struct AssetKey<'a>(pub &'a str);
impl KeySpec for AssetKey<'_> {
    const CF: &'static str = CF_ASSETS;
    type Value = Asset;
    fn encode(&self) -> Vec<u8> {
        format!("asset_record:{}", self.0).into_bytes()
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
/// A maintained index rather than a prefix scan over `asset_record:`, for the
/// same reason `meta:operator_index:` exists: listing is a read path and the
/// codebase resolves column families by key *prefix* (`cf_for_key`), not by
/// `KeySpec::CF`. An index is a single read regardless, and this one lives in
/// `CF_META` since nothing dispatches on it (see `AssetIndexKey`'s exclusion
/// from `is_state_key`).
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

/// One registered attestor's registry record — `CF_ATTESTORS`, included in
/// `is_state_key`, so an address's membership in the trusted set is
/// merkleized and provable in the state root, not just a `CF_META` row a
/// light client has to trust a full node for.
pub struct AttestorRecordKey<'a>(pub &'a Address);
impl KeySpec for AttestorRecordKey<'_> {
    const CF: &'static str = CF_ATTESTORS;
    type Value = AttestorRecord;
    fn encode(&self) -> Vec<u8> {
        format!("attestor_record:{}", self.0).into_bytes()
    }
}

/// Replay-protection marker for a slashed equivocation/fault at `height` by
/// `proposer` — `CF_EVIDENCE`, included in `is_state_key`, so the
/// proof-only adjudicator can read it through `KvRead` like everything else
/// instead of needing a fail-closed stub. Zero-padded height preserves
/// lexicographic range-scan order.
pub struct EvidenceMarkerKey<'a> {
    pub height: u64,
    pub proposer: &'a Address,
}
impl KeySpec for EvidenceMarkerKey<'_> {
    const CF: &'static str = CF_EVIDENCE;
    type Value = ();
    fn encode(&self) -> Vec<u8> {
        format!("evidence:{:020}:{}", self.height, self.proposer).into_bytes()
    }
}

/// This chain's genesis hash, seeded once at genesis — reuses `CF_EVIDENCE`
/// so it is merkleized and provable, letting `dispatch` check a submitted
/// fault artifact's `genesis_hash` against the chain it's actually running on.
pub struct GenesisHashKey;
impl KeySpec for GenesisHashKey {
    const CF: &'static str = CF_EVIDENCE;
    type Value = String;
    fn encode(&self) -> Vec<u8> {
        b"evidence:genesis_hash".to_vec()
    }
}

/// Address allowed to `RegisterAttestor`/`DeregisterAttestor` — see
/// `Snapshot::governor`.
pub struct GovernorKey;
impl KeySpec for GovernorKey {
    const CF: &'static str = CF_META;
    type Value = Address;
    fn encode(&self) -> Vec<u8> {
        b"meta:governor".to_vec()
    }
}

/// Read-only view over typed keys. Never a write path: all writes stay
/// batched through `BatchWritable` in `core/storage`, applied atomically
/// once per block.
pub trait KvRead {
    type Error;
    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, Self::Error>;
}
