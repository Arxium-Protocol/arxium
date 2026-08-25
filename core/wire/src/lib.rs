// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Wire types for the Arxium peer-to-peer block sync protocol.
//!
//! Shared by `arxd/network` and by external indexers, so both sides compile
//! against one definition rather than hand-maintained copies of each other's
//! structs. bincode encodes positionally and carries no version tag: a field
//! added on one side and not the other decodes as garbage rather than failing,
//! which is exactly the failure mode this crate removes.
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

/// libp2p protocol name. Bumped only for a change that is *not* backwards
/// compatible under the rules above.
pub const SYNC_PROTOCOL: &str = "/arxium/sync/1";

/// Incremented whenever a variant is appended, so peers can tell each other
/// apart within one `SYNC_PROTOCOL` generation.
///
/// 1 = `Status` + `Blocks`. 2 = adds `NodeInfo` and `Hashes`.
pub const WIRE_VERSION: u32 = 2;

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
}

/// Generic over the *block* type, not the payload inside it. The protocol only
/// promises to carry blocks in height order; what a block is belongs to the
/// chain. A CoreChain node instantiates this as `SyncResponse<Block<P>>`, while
/// a follower whose chain has a different block envelope supplies its own type
/// and still speaks the same protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse<B> {
    Status { tip_height: u64 },
    Blocks(Vec<B>),
    NodeInfo(NodeInfo),
    /// `(height, hash)` ascending. Truncated to the responder's page size, and
    /// silently short where it has no block — absence is not an error here.
    Hashes(Vec<(u64, String)>),
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
    pub tip_hash: Option<String>,
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
