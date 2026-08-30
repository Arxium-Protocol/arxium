// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use libp2p::PeerId;
use metrics::counter;
use std::time::Duration;
use tracing::warn;
use xc_storage::ArxiumDb;

use crate::transport::Behaviour;

/// Request/response protocol a node uses to catch up on blocks it missed
/// (e.g. was offline for) instead of only ever hearing about the newest
/// block over gossip. Same acceptance path as gossiped blocks — this only
/// adds a second delivery mechanism, not new validation.
///
/// The shapes themselves live in `xc-wire` so external consumers compile
/// against the same definitions instead of copying them; see that crate for the
/// variant-compatibility rules.
pub(crate) use xc_wire::sync_protocol;
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

pub(crate) use xc_wire::{NodeInfo, SyncRequest, SyncResponse};

pub(crate) fn local_tip_height(db: &ArxiumDb) -> u64 {
    db.get_tip_height().ok().flatten().unwrap_or(0)
}

/// Advances the "is the tip stuck" tracker after processing one sync page,
/// and decides whether to keep retrying this peer.
///
/// Pulled out of the sync event loop so the one behavior that actually
/// matters here — a peer that keeps re-serving a page this node can never
/// accept eventually gets cut off instead of retried forever — is a plain
/// function a test can drive without spinning up a swarm. Before this
/// existed, the loop only *logged* once at the cap and then kept
/// request/responding with zero backoff, which is what ran a 40GB disk out
/// of space in production: an unbounded WARN-per-rejected-block loop bounded
/// only by network round-trip time.
///
/// Returns the updated tracker and the number of consecutive rounds the tip
/// has been stuck at its current height (0 if this round made progress).
pub(crate) fn advance_stuck_tip(stuck_tip: Option<(u64, u32)>, local_tip: u64) -> (Option<(u64, u32)>, u32) {
    match stuck_tip {
        Some((height, rounds)) if height == local_tip => {
            let rounds = rounds + 1;
            (Some((height, rounds)), rounds)
        }
        _ => (Some((local_tip, 0)), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_resets_the_stuck_counter() {
        let (state, rounds) = advance_stuck_tip(Some((10, 3)), 11);
        assert_eq!(state, Some((11, 0)));
        assert_eq!(rounds, 0);
    }

    #[test]
    fn no_progress_increments_the_stuck_counter() {
        let (state, rounds) = advance_stuck_tip(Some((10, 3)), 10);
        assert_eq!(state, Some((10, 4)));
        assert_eq!(rounds, 4);
    }

    #[test]
    fn stuck_counter_keeps_climbing_past_the_cap() {
        // Regression check for the production incident: rounds must keep
        // being reported past `MAX_CONSECUTIVE_SYNC_FAILURES` so the caller
        // can cut the peer off on every round past the cap, not just the
        // one round where it was first hit.
        let mut state = Some((10, MAX_CONSECUTIVE_SYNC_FAILURES - 1));
        for expected in MAX_CONSECUTIVE_SYNC_FAILURES..MAX_CONSECUTIVE_SYNC_FAILURES + 3 {
            let (next_state, rounds) = advance_stuck_tip(state, 10);
            assert_eq!(rounds, expected);
            state = next_state;
        }
    }

    #[test]
    fn first_observation_starts_at_zero_rounds() {
        let (state, rounds) = advance_stuck_tip(None, 5);
        assert_eq!(state, Some((5, 0)));
        assert_eq!(rounds, 0);
    }
}

pub(crate) fn send_sync_request(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: &PeerId,
    request: &SyncRequest,
) {
    let kind = match request {
        SyncRequest::Status => "status",
        SyncRequest::Blocks { .. } => "blocks",
        SyncRequest::NodeInfo => "node_info",
        SyncRequest::Hashes { .. } => "hashes",
    };
    match bincode::serde::encode_to_vec(request, bincode::config::standard()) {
        Ok(bytes) => {
            counter!("arxium_sync_requests_total", "kind" => kind).increment(1);
            swarm.behaviour_mut().sync.send_request(peer, bytes);
        }
        Err(err) => warn!("failed to encode sync request: {err}"),
    }
}
