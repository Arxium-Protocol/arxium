use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;
use xc_primitives::Block;
use xc_storage::ArxiumDb;

use crate::transport::Behaviour;

/// Request/response protocol a node uses to catch up on blocks it missed
/// (e.g. was offline for) instead of only ever hearing about the newest
/// block over gossip. Same acceptance path as gossiped blocks — this only
/// adds a second delivery mechanism, not new validation.
pub(crate) const SYNC_PROTOCOL: &str = "/arxium/sync/1";
/// How often a connected peer is re-asked for its tip, to catch a peer
/// falling behind mid-connection (not just "was offline, just reconnected") —
/// e.g. a gossiped block silently dropped rather than erroring, which the
/// OutboundFailure retry above can't see. Kept a small multiple of a
/// devnet-scale block interval (~2s) rather than a long fixed value, so a
/// missed block self-heals in a couple of block times, not tens of seconds.
pub(crate) const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// A peer whose sync requests fail this many times in a row (without a
/// success in between) stops being retried until it reconnects — a flapping
/// connection otherwise retries every single failure immediately, which on a
/// bad link produces dozens of retries per second forever. Past this cap the
/// peer is just skipped by the `STATUS_INTERVAL` tick; `ConnectionEstablished`
/// (a real reconnect) or any successful sync response clears the count.
pub(crate) const MAX_CONSECUTIVE_SYNC_FAILURES: u32 = 5;

/// `Blocks` returns at most `xc_storage::MAX_PAGE_SIZE` blocks starting at
/// `from`, capped at the local tip — never fabricates blocks the responder
/// doesn't have. A node many blocks behind just takes multiple rounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum SyncRequest {
    Status,
    Blocks { from: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum SyncResponse<P> {
    Status { tip_height: u64 },
    Blocks(Vec<Block<P>>),
}

pub(crate) fn local_tip_height(db: &ArxiumDb) -> u64 {
    db.get_tip_height().ok().flatten().unwrap_or(0)
}

pub(crate) fn send_sync_request(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: &PeerId,
    request: &SyncRequest,
) {
    match bincode::serde::encode_to_vec(request, bincode::config::standard()) {
        Ok(bytes) => {
            swarm.behaviour_mut().sync.send_request(peer, bytes);
        }
        Err(err) => warn!("failed to encode sync request: {err}"),
    }
}
