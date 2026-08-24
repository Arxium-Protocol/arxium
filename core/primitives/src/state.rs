use std::collections::BTreeMap;

use crate::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Every raw `u128` amount/balance/stake field on this page is denominated in
// IUM — 1 ARX = 1_000_000_000 IUM, an app-level convention (see `ArxAmount`
// on the Swift side), not a field the chain itself defines.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountEntry {
    pub balance: u128,
    pub nonce: u64,
    pub identity_hash: Option<String>,
    // `#[serde(default)]` so existing RocksDB entries deserialize as `false`
    // without a migration.
    #[serde(default)]
    pub zk_identity_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub stake: u128,
}

/// An in-flight partial unstake on a `StakeAllocation` — v1 allows at most
/// one per `(master, validator)` pair at a time (see `StakeAllocation`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unbonding {
    pub amount: u128,
    pub unlock_at_height: u64,
}

/// A master account's stake into one validator's sub-account
/// (`circuit_staking::stake_subaccount`), owned by `circuit-staking`.
/// `active_amount` and `unbonding` coexist in the same record because a
/// partial unstake leaves part of the stake `Active` while the requested
/// part is `Unbonding` — an either/or status enum can't represent that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeAllocation {
    pub master: Address,
    pub validator: Address,
    pub active_amount: u128,
    pub unbonding: Option<Unbonding>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Deterministically derives the address staked coins for `validator` are
/// held in. Any node computes this locally — no lookup table needed.
///
/// Lives here rather than in `circuit-staking` (which re-exports it for
/// existing callers) because genesis construction (`Snapshot::batch_entries`
/// in `xc-storage`) needs it to fund a genesis validator's sub-account, and
/// `xc-storage` can't depend on `circuit-staking` — `circuit-staking` is the
/// one that depends on `xc-storage`, not the other way around. This function
/// is pure address derivation with no staking logic, so it belongs at the
/// shared base both crates already depend on.
pub fn stake_subaccount(validator: &Address) -> Address {
    // ponytail: domain-separated hash; grep confirmed no other
    // from_pubkey_bytes-as-hash usage in xc-primitives to collide with.
    let preimage = [b"xc-stake-subaccount:".as_slice(), validator.to_string().as_bytes()].concat();
    let digest = Sha256::digest(preimage);
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// Deterministic reward-pool sub-account, same derivation scheme as
/// `stake_subaccount` and the same reason for living here — genesis needs to
/// pre-fund it (see `devnet.json`'s `accounts` entry, credited directly by
/// address) without a `circuit-staking` dependency.
pub fn reward_pool_account() -> Address {
    let digest = Sha256::digest(b"xc-reward-pool");
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// Deterministic protocol-treasury sub-account, same derivation scheme.
pub fn treasury_account() -> Address {
    let digest = Sha256::digest(b"xc-treasury");
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
}

/// A membership change to the round-robin validator set, produced by a
/// chain-specific dispatch (e.g. `ActionPayload::JoinValidator`) and applied
/// generically by `xc_executor::accept_block`/`produce_block` — chain-agnostic
/// like `expected_proposer` itself, since any `P`-chain wanting round-robin
/// PoS needs the same join/leave bookkeeping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorChange {
    Join(Address, ValidatorEntry),
    Leave(Address),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub height: u64,
    pub chain_name: String,
    pub accounts: BTreeMap<Address, AccountEntry>,
    pub validators: BTreeMap<Address, ValidatorEntry>,
    /// Peer multiaddrs new nodes dial on startup to join this chain, same
    /// role as a Polkadot chain-spec's `bootNodes` — part of the chain
    /// identity, not a per-run CLI concern. `--bootnodes` on the command
    /// line overrides this list entirely when given; empty here means rely
    /// on mDNS or an explicit CLI override.
    #[serde(default)]
    pub boot_nodes: Vec<String>,
}
