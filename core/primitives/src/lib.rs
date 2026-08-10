use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;

mod action;
mod address;
mod block;
mod consensus;
mod state;

pub use action::{Action, ActionPayload, SignatureError};
pub use address::{Address, AddressError};
pub use block::Block;
pub use consensus::expected_proposer;
pub use state::{AccountEntry, Snapshot, ValidatorEntry};

#[derive(Debug)]
pub struct NodeConfig {
    pub base_path: PathBuf,
    pub port: u16,
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
