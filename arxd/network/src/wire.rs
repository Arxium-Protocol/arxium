// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Wire types for the Arxium peer-to-peer block sync protocol.
//!
//! `pub` so the fuzz targets decode the exact shapes the node does. bincode
//! encodes positionally and carries no version tag: a field added on one side
//! and not the other decodes as garbage rather than failing, so the rules
//! below matter for every peer on the network.
//!
//! ## Compatibility rules
//!
//! bincode identifies enum variants by their index, so:
//!
//! * **Append** new variants; never reorder or remove existing ones.
//! * **Never** add a field to an existing variant — that changes its encoding
//!   for every peer. Add a new variant instead.
//!
//! A peer that receives a variant it doesn't know fails to decode it and logs a
//! warning, which is safe: only a peer that understands a variant ever sends
//! it. Combined with [`WIRE_VERSION`] in [`NodeInfo`], that makes an old/new
//! mismatch visible rather than silent.

use serde::{Deserialize, Serialize};
use xc_primitives::Hash32;

/// libp2p protocol name, chain-scoped so two nodes on different chains can't
/// open a sync stream and exchange blocks that fail verification — the same
/// isolation gossip topics already get (see `arxd/network/src/gossip.rs`).
/// Bumped (the `/1` segment) only for a change that is *not* backwards
/// compatible under the rules above.
pub fn sync_protocol(chain_id: &str) -> String {
    format!("/arxium/sync/1/{chain_id}")
}

/// Incremented whenever a variant is appended, so peers can tell each other
/// apart within one `SYNC_PROTOCOL` generation.
///
/// 1 = `Status` + `Blocks`. 2 = adds `NodeInfo` and `Hashes`. 3 = adds
/// `Certificate`. 4 = adds `SnapshotManifest` and `SnapshotChunk`.
pub const WIRE_VERSION: u32 = 4;

/// `Blocks` returns at most the responder's page size (see
/// [`NodeInfo::max_page_size`]) starting at `from`, capped at its local tip —
/// it never fabricates blocks it doesn't have. A peer many blocks behind just
/// takes several rounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    Status,
    Blocks {
        from: u64,
    },
    /// What this peer is and what it knows — finality, page size, wire version.
    /// Everything an indexer previously had to hardcode or infer.
    NodeInfo,
    /// Block hashes for `from..=to`, without the block bodies.
    ///
    /// Exists for fork resolution. Without it a follower that disagrees with a
    /// peer can only peel one block per round trip, because the only way to
    /// learn a hash is to download the whole block. With it, the common
    /// ancestor is a binary search over a cheap range.
    Hashes {
        from: u64,
        to: u64,
    },
    /// The responder's finality certificate at `height`, if it has one.
    ///
    /// Exists for divergence recovery. A peer's *claim* that its chain is the
    /// right one is worth nothing; a certificate the asker can verify against
    /// the validator set it independently holds at that height is the only
    /// thing that justifies rewriting local history, so it has to be
    /// fetchable on its own rather than inferred from block bodies.
    Certificate {
        height: u64,
    },
    /// Snapshot sync: describe the responder's state as of `height`, so a
    /// joining node can skip replaying history. The asker names the height
    /// (its operator's trust anchor); the responder can only answer for a
    /// height it can still reconstruct — see `xc_storage::UNDO_RETAIN`.
    SnapshotManifest {
        height: u64,
    },
    /// One chunk of the snapshot a `SnapshotManifest` described.
    SnapshotChunk {
        height: u64,
        index: u32,
    },
}

/// One raw `(column family, key, value)` row of a node's state, exactly as
/// `xc_storage` stores it. Opaque here: the importer verifies the whole set
/// against a certified state root, never one row.
pub type SnapshotEntry = (String, Vec<u8>, Vec<u8>);

/// Answer to [`SyncRequest::SnapshotManifest`]. The block and its finality
/// certificate ride along bincode-encoded (opaque here, as `Certificate` is)
/// so the asker can tie `state_root` to the block its trust anchor names and
/// to a quorum of the validator set the snapshot itself carries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub height: u64,
    pub block_hash: Hash32,
    pub state_root: String,
    pub entries: u64,
    pub chunks: u32,
    /// SHA-256 of each chunk's bincode-encoded entry list — an IO checksum
    /// against a corrupt or truncated chunk, *not* a trust anchor (the
    /// responder chose them). Trust comes from the root check on import.
    pub chunk_hashes: Vec<[u8; 32]>,
    pub block: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// Generic over the *block* type, not the payload inside it. The protocol only
/// promises to carry blocks in height order; what a block is belongs to the
/// chain. A CoreChain node instantiates this as `SyncResponse<Block<P>>`, while
/// a follower whose chain has a different block envelope supplies its own type
/// and still speaks the same protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse<B> {
    Status {
        tip_height: u64,
    },
    Blocks(Vec<B>),
    NodeInfo(NodeInfo),
    /// `(height, hash)` ascending. Truncated to the responder's page size, and
    /// silently short where it has no block — absence is not an error here.
    Hashes(Vec<(u64, Hash32)>),
    /// Answer to [`SyncRequest::Certificate`]. `record` is a bincode-encoded
    /// finality certificate, opaque here so this crate stays free of chain
    /// crypto types; `None` means the responder has no certificate at that
    /// height, which is not an error. The asker must verify what it decodes —
    /// nothing about arriving over this protocol makes a certificate valid.
    Certificate {
        height: u64,
        record: Option<Vec<u8>>,
    },
    /// `None`: the responder cannot serve that height (above its tip, not
    /// certified, or its undo window has passed it) — not an error, ask
    /// another peer or pick a newer anchor.
    SnapshotManifest(Option<SnapshotManifest>),
    /// `None` entries: same as above, or an index past `chunks`.
    SnapshotChunk {
        height: u64,
        index: u32,
        entries: Option<Vec<SnapshotEntry>>,
    },
}

/// A peer's self-description.
///
/// Every field here replaces something a consumer previously had to assume.
/// `max_page_size` was a constant copied between repos with a comment asking
/// people to keep it in sync; `finalized_height` was approximated by a
/// configurable "finality depth" guess; `tip_hash` was unobtainable without
/// downloading the tip block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub wire_version: u32,
    pub tip_height: u64,
    /// Content hash at `tip_height`. `None` only if the tip can't be read.
    pub tip_hash: Option<Hash32>,
    /// Highest height holding a finality certificate (2/3+ of that height's
    /// validator set precommitted), or `None` on a chain that doesn't run
    /// finality voting.
    ///
    /// A follower can treat blocks at or below this as safe from reorg without
    /// guessing at a depth. Certificates complete as quorums are reached, which
    /// is not strictly in height order, so this is the highest *certified*
    /// height rather than a watermark below which everything is certified.
    pub finalized_height: Option<u64>,
    /// Most blocks or hashes a single `Blocks`/`Hashes` response will carry.
    pub max_page_size: u32,
}
