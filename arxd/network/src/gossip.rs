use libp2p::PeerId;
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

/// One pub/sub topic for actions — gossip is just another untrusted entry
/// point into the mempool, no more trusted than a stranger hitting RPC.
pub(crate) const ACTIONS_TOPIC: &str = "arxium/actions/v1";
/// One pub/sub topic for blocks. Validation (signature, expected proposer,
/// parent hash) happens in the caller-supplied `on_block` callback — this
/// crate doesn't know how to execute a chain's actions, only how to move
/// bytes between peers.
pub(crate) const BLOCKS_TOPIC: &str = "arxium/blocks/v1";
/// One pub/sub topic for BLS precommit votes (`finality::PrecommitVote`) —
/// same "gossip is just another untrusted entry point" rule as actions;
/// signature/voter/quorum validation happens in `arxd/finality`, not here.
pub(crate) const PRECOMMITS_TOPIC: &str = "arxium/precommits/v1";

/// A peer sending this many unambiguously-bad gossip messages (undecodable
/// bytes, forged signatures) in a row gets disconnected — see
/// `record_bad_gossip`.
pub(crate) const MAX_BAD_GOSSIP: u32 = 10;

/// Records gossip that's unambiguously bad — undecodable bytes or a forged
/// signature, never just "this peer is a bit behind" — and disconnects the
/// peer once it crosses `MAX_BAD_GOSSIP`, so a hostile peer can't spam
/// garbage at zero cost forever. `ConnectionEstablished` clears the count on
/// reconnect, same as `sync_failures`.
pub(crate) fn record_bad_gossip(
    swarm: &mut libp2p::Swarm<Behaviour>,
    bad_gossip: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    reason: &str,
) {
    let count = bad_gossip.entry(peer).or_insert(0);
    *count += 1;
    if *count >= MAX_BAD_GOSSIP {
        warn!("disconnecting {peer}: {reason} ({count} bad gossip messages)");
        let _ = swarm.disconnect_peer_id(peer);
    } else {
        warn!("{reason} from {peer} ({count}/{MAX_BAD_GOSSIP})");
    }
}
