use std::collections::BTreeMap;

use crate::Address;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountEntry {
    pub balance: u128,
    pub nonce: u64,
    pub identity_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub stake: u128,
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
