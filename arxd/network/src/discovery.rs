// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use libp2p::{Multiaddr, PeerId};
use tracing::{info, warn};

use crate::transport::Behaviour;

pub(crate) fn dial_bootnodes(swarm: &mut libp2p::Swarm<Behaviour>, bootnodes: Vec<Multiaddr>) {
    for addr in bootnodes {
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!("failed to dial bootnode {addr}: {err}");
        }
    }
}

/// Dials only the TCP entry. mdns reports one per transport (tcp + quic), and
/// a QUIC connection outlives a killed peer until its idle timeout: when the
/// peer restarts inside that window, gossipsub still counts the dead
/// connection, treats the new one as a second connection to a known peer, and
/// never sends it this node's topic subscriptions — so the restarted peer
/// publishes nothing to us, for good (seen as a two-validator stall in
/// `scripts/two-node-restart-harness.sh`). A killed process's TCP connection
/// closes at once. Bootnodes are TCP already.
pub(crate) fn dial_discovered(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peers: Vec<(PeerId, Multiaddr)>,
) {
    for (peer_id, addr) in peers {
        info!("mdns discovered peer {peer_id} at {addr}");
        if !is_tcp(&addr) {
            continue;
        }
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!("failed to dial discovered peer {peer_id} at {addr}: {err}");
        }
    }
}

fn is_tcp(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_tcp_entry_of_an_mdns_pair_is_dialed() {
        let tcp: Multiaddr = "/ip4/192.168.1.2/tcp/30334".parse().unwrap();
        let quic: Multiaddr = "/ip4/192.168.1.2/udp/30334/quic-v1".parse().unwrap();
        assert!(is_tcp(&tcp));
        assert!(!is_tcp(&quic));
    }
}
