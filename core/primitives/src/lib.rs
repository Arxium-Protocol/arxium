// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;

mod action;
mod address;
mod block;
mod consensus;
pub mod keyfile;
mod state;

pub use action::{Action, RawAction, SignatureError};
pub use address::{Address, AddressError};
pub use block::{Block, RawBlock};
pub use consensus::{
    MAX_FUTURE_DRIFT_SECS, RoundCertificate, eligible_proposer, expected_proposer, quorum,
    round_timeout_signing_bytes,
};
pub use state::{
    reward_pool_account, stake_subaccount, treasury_account, AccountEntry, Asset, AttestorRecord,
    Snapshot, StakeAllocation, Unbonding, ValidatorChange, ValidatorEntry,
};

/// Ceiling for any single bincode-decoded value read from untrusted bytes
/// (gossip, sync responses, fault evidence) before a signature check has run.
/// Matches `arxd_network::transport::MAX_GOSSIP_TRANSMIT_SIZE` — kept here
/// (not there) so every decode site in both `arxd` and downstream readers
/// (e.g. Retracer) shares one number instead of picking limits independently.
/// `arxd_network` re-exports its constant as this value so the two can never
/// drift apart.
pub const MAX_WIRE_MESSAGE_SIZE: usize = 1024 * 1024;

/// Standard bincode config for decoding untrusted bytes: same as
/// `bincode::config::standard()` but with `MAX_WIRE_MESSAGE_SIZE` applied, so
/// a peer can't force a huge allocation by declaring an oversized
/// length-prefixed field (e.g. `Action<P>`'s payload `Vec<u8>`) before the
/// read actually fails.
pub fn wire_config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<MAX_WIRE_MESSAGE_SIZE>()
}

/// The one decode for peer-supplied bytes: `wire_config()`'s size limit, no
/// trailing bytes, and canonical encoding.
///
/// The canonical check is the one fuzzing (`fuzz/fuzz_targets`) argued for.
/// bincode's varint decoder accepts a non-minimal encoding — `0` may arrive
/// as `00` or as `fb 00 00` — while its encoder only ever emits the minimal
/// form, so without this one value has unboundedly many valid wire
/// representations. Nothing about that is a memory-safety bug, which is why
/// review never caught it, but it hands an attacker a cheap re-encoding
/// oracle: the same block re-broadcast under a fresh gossipsub message id
/// every time (message ids hash the bytes, so a duplicate no longer looks
/// like one), and any check that compares supplied bytes against a
/// re-encoding of what they decoded to has two answers to choose from.
/// Every honest producer encodes through `wire_config()` and is already
/// canonical, so this rejects nothing a peer legitimately sends.
///
/// Costs one extra encode per received message — cheaper than the signature
/// verification that follows it on every one of these paths.
pub fn decode_wire_canonical<T>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let (value, consumed) = bincode::serde::decode_from_slice(bytes, wire_config())?;
    if consumed != bytes.len() {
        return Err(bincode::error::DecodeError::Other("trailing bytes after decoded value"));
    }
    let canonical = bincode::serde::encode_to_vec(&value, wire_config())
        .map_err(|_| bincode::error::DecodeError::Other("value did not re-encode"))?;
    if canonical != bytes {
        return Err(bincode::error::DecodeError::Other("non-canonical encoding"));
    }
    Ok(value)
}

/// Resource limits an operator can raise or lower per deployment. Every
/// default is the devnet-sized value these used to be hardcoded at, so an
/// unconfigured node behaves exactly as before; the point is that a node
/// exposed to strangers no longer needs a rebuild to be tuned. Set through
/// `arxd`'s `--rpc-*`/`--mempool-*`/`--max-peers-incoming` flags or their
/// `ARXD_*` environment variables.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest single JSON action body the RPC will read.
    pub rpc_max_body_bytes: usize,
    /// Rate-limit window, and the per-IP budget of write and read requests
    /// inside it. Per RPC *instance* and in memory only — see
    /// `xc_rpc::RateLimiter`.
    pub rpc_rate_limit_window_secs: u64,
    pub rpc_rate_limit_writes: u32,
    pub rpc_rate_limit_reads: u32,
    /// How many trusted reverse proxies sit in front of the RPC, each
    /// appending to `X-Forwarded-For`. 0 (the default) keys rate limiting on
    /// the socket address and ignores the header entirely — see
    /// `xc_rpc::client_ip`.
    pub rpc_trusted_proxy_hops: usize,
    /// Mempool admission caps: entries, and total encoded bytes. Raise both
    /// together — a count cap alone lets a few huge actions exhaust memory.
    pub mempool_max_pending: usize,
    pub mempool_max_bytes: usize,
    /// Mempool slots any single sender may hold at once. Without it one
    /// account can fill the whole queue: admission is FIFO against the global
    /// caps, with no fee-priority eviction.
    pub mempool_max_per_sender: usize,
    /// How far ahead of a sender's on-chain nonce an action may be and still
    /// be admitted. An action beyond it cannot execute until the gap is
    /// filled, so without a bound a sender can queue actions that are
    /// permanently unexecutable and never purged as stale.
    pub mempool_max_nonce_gap: u64,
    /// Concurrent inbound P2P connections this node will hold.
    pub max_peers_incoming: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rpc_max_body_bytes: 64 * 1024,
            rpc_rate_limit_window_secs: 60,
            rpc_rate_limit_writes: 60,
            rpc_rate_limit_reads: 600,
            rpc_trusted_proxy_hops: 0,
            mempool_max_pending: 10_000,
            mempool_max_bytes: 10_000_000,
            mempool_max_per_sender: 64,
            mempool_max_nonce_gap: 64,
            max_peers_incoming: 200,
        }
    }
}

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
    pub limits: Limits,
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

#[cfg(test)]
mod wire_decode_tests {
    use super::*;

    /// The exact input fuzzing found: `height: 0` written as bincode's
    /// non-minimal varint (`fb 00 00`) instead of `00`. bincode decodes it
    /// happily, so without the canonical check every value on the wire has
    /// unboundedly many spellings.
    #[test]
    fn a_non_canonical_varint_is_rejected() {
        let block = Block::<()>::genesis(0);
        let canonical = bincode::serde::encode_to_vec(&block, wire_config()).unwrap();
        assert_eq!(canonical[0], 0x00, "height 0 encodes minimally");

        let mut non_canonical = vec![0xfb, 0x00, 0x00];
        non_canonical.extend_from_slice(&canonical[1..]);

        assert!(
            bincode::serde::decode_from_slice::<Block<()>, _>(&non_canonical, wire_config()).is_ok(),
            "bincode itself accepts it — that is why this guard exists"
        );
        assert!(decode_wire_canonical::<Block<()>>(&non_canonical).is_err());
        assert!(decode_wire_canonical::<Block<()>>(&canonical).is_ok());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let block = Block::<()>::genesis(0);
        let mut padded = bincode::serde::encode_to_vec(&block, wire_config()).unwrap();
        padded.push(0);
        assert!(decode_wire_canonical::<Block<()>>(&padded).is_err());
    }
}
