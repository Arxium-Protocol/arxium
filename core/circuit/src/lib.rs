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
use xc_primitives::{AccountEntry, Address, Asset, AssetRef, AttestorRecord, HolderState, StakeAllocation};

pub const CF_META: &str = "meta";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_ASSETS: &str = "assets";
pub const CF_ATTESTORS: &str = "attestors";
pub const CF_EVIDENCE: &str = "evidence";
pub const CF_GOVERNANCE: &str = "governance";

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
/// exclusively "owned" by one circuit. Lives in `CF_GOVERNANCE` (included in
/// `is_state_key`) so `JoinValidator`/`RegisterBlsKey` are provable to the
/// proof-only adjudicator instead of sitting in `CF_META`. The rotation
/// history (`meta:blskey_hist:{addr}:{height}`, read via range scan in
/// `get_bls_pubkey_at`) stays in `CF_META` — range scans have no proof shape.
pub struct BlsKeyKey<'a>(pub &'a Address);
impl KeySpec for BlsKeyKey<'_> {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = BlsPublicKey;
    fn encode(&self) -> Vec<u8> {
        format!("blskey:{}", self.0).into_bytes()
    }
}

/// Reverse of `BlsKeyKey`: which address currently owns a given BLS pubkey,
/// so the duplicate-registration check in `JoinValidator`/`RegisterBlsKey`
/// (previously a `CF_META` linear scan, see `ArxiumDb::bls_pubkey_owner`) is a
/// single provable key read instead. Written and deleted alongside
/// `BlsKeyKey` (see `BlsKeyRegistration::batch_entries`/`batch_deletes`) so a
/// rotated-away-from pubkey is freed for reuse, mirroring the old scan's
/// self-healing behavior.
pub struct BlsPubkeyOwnerKey<'a>(pub &'a BlsPublicKey);
impl KeySpec for BlsPubkeyOwnerKey<'_> {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = Address;
    fn encode(&self) -> Vec<u8> {
        format!("blskey_owner:{}", hex::encode(self.0.0)).into_bytes()
    }
}

/// The address currently authorized to submit `JoinValidator`/
/// `LeaveValidator`/`RegisterBlsKey` on `validator`'s behalf, if any. Lives in
/// `CF_GOVERNANCE` (included in `is_state_key`) so the delegated paths of
/// those three actions are provable to the adjudicator.
pub struct OperatorKey<'a>(pub &'a Address);
impl KeySpec for OperatorKey<'_> {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = Address;
    fn encode(&self) -> Vec<u8> {
        format!("operator:{}", self.0).into_bytes()
    }
}

/// The reverse of `OperatorKey`: every validator currently authorizing
/// `operator`. Read by `AuthorizeOperator`/`RevokeOperator` to maintain the
/// list, so — unlike `AssetIndexKey`, which nothing dispatches on — it is
/// `CF_GOVERNANCE` and in the root: the adjudicator has to be able to replay
/// those two actions, and it can't from a `CF_META` row.
pub struct OperatorIndexKey<'a>(pub &'a Address);
impl KeySpec for OperatorIndexKey<'_> {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = Vec<Address>;
    fn encode(&self) -> Vec<u8> {
        format!("operator_index:{}", self.0).into_bytes()
    }
}

/// The stake-weighted validator set effective from `height` — the row
/// `xc_storage::ValidatorSetSnapshot` writes. `CF_VALIDATORS`, merkleized.
/// The boundary hook writes one at *every* boundary, so the set in force at
/// any height `H` is at exactly `validator_set_effective_height(H)` and an
/// adjudicator can prove it as a single key instead of needing the
/// reverse-seek `get_validator_set_at` does.
pub struct ValidatorSetKey(pub u64);
impl KeySpec for ValidatorSetKey {
    const CF: &'static str = CF_VALIDATORS;
    type Value = std::collections::BTreeMap<Address, xc_primitives::VotingPower>;
    fn encode(&self) -> Vec<u8> {
        format!("validator_set:{:020}", self.0).into_bytes()
    }
}

/// The registry record for a regulated asset — `issuer`/`compliance_required`,
/// not its balances (see `AssetBalanceKey`). Lives in `CF_ASSETS` (included in
/// `is_state_key`) so `compliance_required` is merkleized and provable to a
/// light client instead of sitting in `CF_META`.
///
/// Keyed on the derived `AssetRef`, not the issuer-chosen `asset_id`: the ref
/// already commits to `(issuer, asset_id)`, so a per-issuer duplicate is
/// simply an existing record at the derived key — no separate alias index is
/// needed to answer "does this issuer already have a `gold`". Every other
/// asset key below follows the same rule. Prefixes are unchanged so
/// `cf_for_key`'s routing is untouched.
pub struct AssetKey<'a>(pub &'a AssetRef);
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
    pub asset: &'a AssetRef,
    pub owner: &'a Address,
}
impl KeySpec for AssetBalanceKey<'_> {
    const CF: &'static str = CF_ASSETS;
    type Value = u128;
    fn encode(&self) -> Vec<u8> {
        format!("asset_balance:{}:{}", self.asset, self.owner).into_bytes()
    }
}

/// Issuer-controlled per-holder compliance state for one asset (see
/// `HolderState`). `CF_ASSETS`, merkleized: whether a holder is frozen is a
/// fact a light client may need to prove.
pub struct AssetHolderStateKey<'a> {
    pub asset: &'a AssetRef,
    pub holder: &'a Address,
}
impl KeySpec for AssetHolderStateKey<'_> {
    const CF: &'static str = CF_ASSETS;
    type Value = HolderState;
    fn encode(&self) -> Vec<u8> {
        format!("asset_holder:{}:{}", self.asset, self.holder).into_bytes()
    }
}

/// Every address holding a non-zero balance of one asset — the cap table.
/// Same reasoning as `AccountAssetsKey`: a maintained `CF_META` index, not a
/// scan and not part of the state root.
pub struct AssetHoldersKey<'a>(pub &'a AssetRef);
impl KeySpec for AssetHoldersKey<'_> {
    const CF: &'static str = CF_META;
    type Value = Vec<Address>;
    fn encode(&self) -> Vec<u8> {
        format!("meta:asset_holders:{}", self.0).into_bytes()
    }
}

/// Every registered asset ref, as one list.
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
    type Value = Vec<AssetRef>;
    fn encode(&self) -> Vec<u8> {
        b"meta:asset_index".to_vec()
    }
}

/// Every asset ref `owner` holds a balance row for.
///
/// The reverse of `AssetBalanceKey`, which is keyed `{asset_ref}:{owner}` and
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
    type Value = Vec<AssetRef>;
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

/// This chain's genesis hash — block 0's state root — seeded once at genesis
/// so `dispatch` can check a submitted fault artifact's `genesis_hash`
/// against the chain it is actually running on.
///
/// `CF_META`, *not* a merkleized state key, and that is forced rather than
/// chosen: the value is the genesis state root itself, so storing it in a
/// key `is_state_key` covers would change the very root it records. This is
/// the one CF_META row of its kind left that structurally can never move —
/// unlike the old `GovernorKey` (now `AdminKey`), which was in the same "genesis-seeded, CF_META,
/// read through `KvRead` at dispatch time" shape but had no such obstacle and
/// has since moved to `CF_GOVERNANCE`.
pub struct GenesisHashKey;
impl KeySpec for GenesisHashKey {
    const CF: &'static str = CF_META;
    type Value = String;
    fn encode(&self) -> Vec<u8> {
        b"meta:genesis_hash".to_vec()
    }
}

/// A validator's standing with respect to the active set — see
/// `xc_primitives::ValidatorStatus`. `CF_VALIDATORS`, merkleized: it decides
/// who the next epoch's set may contain, and `Tombstoned` is the permanent
/// bar to re-entry, so both must be provable.
pub struct ValidatorStatusKey<'a>(pub &'a Address);
impl KeySpec for ValidatorStatusKey<'_> {
    const CF: &'static str = CF_VALIDATORS;
    type Value = xc_primitives::ValidatorStatus;
    fn encode(&self) -> Vec<u8> {
        format!("validator_status:{}", self.0).into_bytes()
    }
}

/// Genesis-fixed consensus parameters (`Snapshot::params`), read at dispatch
/// and at every epoch boundary. `CF_GOVERNANCE` so they are in the root.
pub struct ChainParamsKey;
impl KeySpec for ChainParamsKey {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = xc_primitives::ChainParams;
    fn encode(&self) -> Vec<u8> {
        b"chain_params".to_vec()
    }
}

/// The three privileged roles that used to be one `governor` address —
/// split so the party that decides who may act as a KYC provider, the
/// party that can halt an instrument, and the party that can move a
/// balance without its owner's signature are independently checkable
/// keys. See `Snapshot::attestor_admin`/`freeze_admin`/`recovery_admin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRole {
    /// `RegisterAttestor`/`DeregisterAttestor`.
    Attestor,
    /// `FreezeAsset`/`UnfreezeAsset` (alongside the asset's own issuer).
    Freeze,
    /// `ForcedTransfer`.
    Recovery,
}

impl AdminRole {
    pub fn name(self) -> &'static str {
        match self {
            AdminRole::Attestor => "attestor admin",
            AdminRole::Freeze => "freeze admin",
            AdminRole::Recovery => "recovery admin",
        }
    }
}

/// Address holding `AdminRole`, seeded at genesis. Lives in
/// `CF_GOVERNANCE` (included in `is_state_key`) so the gated actions are
/// provable to the proof-only adjudicator instead of failing closed.
pub struct AdminKey(pub AdminRole);
impl KeySpec for AdminKey {
    const CF: &'static str = CF_GOVERNANCE;
    type Value = Address;
    fn encode(&self) -> Vec<u8> {
        match self.0 {
            AdminRole::Attestor => b"admin:attestor".to_vec(),
            AdminRole::Freeze => b"admin:freeze".to_vec(),
            AdminRole::Recovery => b"admin:recovery".to_vec(),
        }
    }
}

/// Read-only view over typed keys. Never a write path: all writes stay
/// batched through `BatchWritable` in `core/storage`, applied atomically
/// once per block.
pub trait KvRead {
    type Error;
    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, Self::Error>;
}
