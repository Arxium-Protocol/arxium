// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;

mod action;
mod address;
mod block;
mod consensus;
mod state;

pub use action::{Action, SignatureError};
pub use address::{Address, AddressError};
pub use block::Block;
pub use consensus::{MAX_FUTURE_DRIFT_SECS, eligible_proposer, expected_proposer, quorum};
pub use state::{
    reward_pool_account, stake_subaccount, treasury_account, AccountEntry, Snapshot,
    StakeAllocation, Unbonding, ValidatorChange, ValidatorEntry,
};

#[derive(Debug)]
pub struct NodeConfig {
    pub base_path: PathBuf,
    /// Chain to run: a built-in preset name (`devnet`, `local`) or a path to
    /// a JSON chain spec — resolved against the running binary's own
    /// `xc_chain_spec::presets::PresetRegistry` by `xc_chain_spec::resolve_chain_spec`.
    /// Kept as a plain string rather than a pre-parsed enum: telling a
    /// preset name from a file path needs the registry in hand (a preset
    /// name must be checked against the registry before ever falling back to
    /// a same-named file), and `xc-primitives` never depends on `xc-chain-spec`.
    pub chain: String,
    pub port: u16,
    /// Port for the P2P (libp2p) listener — TCP and QUIC. Separate from
    /// `port` (the RPC listener) since they're independent services.
    pub p2p_port: u16,
    /// Explicit peer addresses (multiaddrs) to dial on startup, for
    /// discovery beyond same-LAN mDNS.
    pub bootnodes: Vec<String>,
    /// DEVNET ONLY — makes this node use the well-known, seed-pinned network
    /// identity that every other node's default `--bootnodes` value expects
    /// to find at a fixed PeerId. See `arxd_network::identity::DEVNET_BOOTNODE_SEED`.
    pub is_bootnode: bool,
    pub is_validator: bool,
    /// If set, the RPC server requires `Authorization: Bearer <token>` on every request.
    pub rpc_token: Option<String>,
    /// Address the RPC server binds to. Loopback by default — production
    /// deployments should sit behind a TLS-terminating reverse proxy.
    pub rpc_bind: String,
}

// --- 2. The Key Types ---
// These types are used by core/consensus and core/network.
pub struct ArxiumKeypair {
    pub node_key: SigningKey,
    pub validator_key: Option<SigningKey>,
}

impl ArxiumKeypair {
    pub fn node_public_key(&self) -> VerifyingKey {
        self.node_key.verifying_key()
    }
}
