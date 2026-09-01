// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use libp2p::PeerId;
use metrics::counter;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tracing::warn;

use crate::transport::Behaviour;

/// Bound the chain's payload type must satisfy to travel over gossip:
/// bincode (de)serializable for the wire, `Send + Sync + 'static` to cross
/// into the swarm's own thread.
pub trait Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> Payload for P {}

/// Topic names are suffixed with the chain's genesis hash (short hex, passed
/// in by the caller) rather than fixed strings, so two nodes booted from
/// different genesis specs land on different gossipsub topics and simply
/// never see each other's messages — instead of connecting at the libp2p
/// layer (identity has nothing to do with which chain a node runs) and only
/// then rejecting every gossiped block/action/vote one at a time.

/// One pub/sub topic for actions — gossip is just another untrusted entry
/// point into the mempool, no more trusted than a stranger hitting RPC.
pub(crate) fn actions_topic(chain_id: &str) -> String {
    format!("arxium/actions/v1/{chain_id}")
}
/// One pub/sub topic for blocks. Validation (signature, expected proposer,
/// parent hash) happens in the caller-supplied `on_block` callback — this
/// crate doesn't know how to execute a chain's actions, only how to move
/// bytes between peers.
pub(crate) fn blocks_topic(chain_id: &str) -> String {
    format!("arxium/blocks/v1/{chain_id}")
}
/// One pub/sub topic for BLS precommit votes (`arxd_finality::PrecommitVote`) —
/// same "gossip is just another untrusted entry point" rule as actions;
/// signature/voter/quorum validation happens in `arxd/finality`, not here.
pub(crate) fn precommits_topic(chain_id: &str) -> String {
    format!("arxium/precommits/v1/{chain_id}")
}
/// One pub/sub topic for dissents (`arxd_finality::Dissent`) — same rule as
/// precommits: signature/voter/one-per-height validation happens in
/// `arxd/finality`, not here.
pub(crate) fn dissents_topic(chain_id: &str) -> String {
    format!("arxium/dissents/v1/{chain_id}")
}
/// One pub/sub topic for round-timeout votes
/// (`arxd_finality::RoundTimeoutVote`) — same rule as precommits: signature/
/// voter/quorum validation happens in `arxd/finality`, not here. See
/// `Arxium_OpenItems.md` §7 (B1b).
pub(crate) fn round_timeouts_topic(chain_id: &str) -> String {
    format!("arxium/round_timeouts/v1/{chain_id}")
}

/// A peer sending this many unambiguously-bad gossip messages (undecodable
/// bytes, forged signatures) in a row gets banned — see `record_bad_gossip`.
pub(crate) const MAX_BAD_GOSSIP: u32 = 10;

/// Records gossip that's unambiguously bad — undecodable bytes or a forged
/// signature, never just "this peer is a bit behind" — and bans the peer
/// once it crosses `MAX_BAD_GOSSIP`, so a hostile peer can't spam garbage at
/// zero cost forever. Deliberately *not* cleared on `ConnectionEstablished`
/// (unlike `sync_failures`, which tracks honest transient failures): this
/// counter exists specifically to survive reconnects, otherwise a peer about
/// to hit the cap can just drop and redial to reset it to zero and keep
/// spamming indefinitely. Once banned, `blocked_peers` (an
/// `allow_block_list::Behaviour`) refuses the peer at the swarm level, so a
/// redial doesn't even get a fresh connection to spam a few more messages on
/// before being cut off again.
pub(crate) fn record_bad_gossip(
    swarm: &mut libp2p::Swarm<Behaviour>,
    bad_gossip: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    topic: &str,
    reason: &str,
) {
    counter!("arxium_gossip_rejected_total", "topic" => topic.to_string(), "reason" => "bad")
        .increment(1);
    let count = bad_gossip.entry(peer).or_insert(0);
    *count += 1;
    if *count >= MAX_BAD_GOSSIP {
        warn!("banning {peer}: {reason} ({count} bad gossip messages)");
        swarm.behaviour_mut().blocked_peers.block_peer(peer);
        counter!("arxium_gossip_peers_banned_total").increment(1);
    } else {
        warn!("{reason} from {peer} ({count}/{MAX_BAD_GOSSIP})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::build_swarm;

    /// Regression check for the reconnect ban-bypass: a peer that
    /// accumulates `MAX_BAD_GOSSIP` reports across separate calls (standing
    /// in for separate connections, since `run_swarm` no longer resets this
    /// map on `ConnectionEstablished`) ends up in `blocked_peers`, and a
    /// peer that stays under the cap does not.
    #[tokio::test]
    async fn crossing_threshold_bans_peer_permanently() {
        let mut swarm =
            build_swarm(libp2p::identity::Keypair::generate_ed25519(), "test-chain").unwrap();
        let mut bad_gossip = HashMap::new();
        let peer = PeerId::random();

        for _ in 0..MAX_BAD_GOSSIP - 1 {
            record_bad_gossip(&mut swarm, &mut bad_gossip, peer, "test", "test");
        }
        assert!(!swarm.behaviour().blocked_peers.blocked_peers().contains(&peer));

        record_bad_gossip(&mut swarm, &mut bad_gossip, peer, "test", "test");
        assert!(swarm.behaviour().blocked_peers.blocked_peers().contains(&peer));
    }
}
