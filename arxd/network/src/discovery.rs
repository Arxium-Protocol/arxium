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

/// ponytail: mdns reports one entry per transport (tcp + quic), so a
/// discovered peer gets dialed twice and briefly shows two connections.
/// Harmless while nothing beyond gossip messages is exchanged over them;
/// collapse to one dial per peer if that changes.
pub(crate) fn dial_discovered(swarm: &mut libp2p::Swarm<Behaviour>, peers: Vec<(PeerId, Multiaddr)>) {
    for (peer_id, addr) in peers {
        info!("mdns discovered peer {peer_id} at {addr}");
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!("failed to dial discovered peer {peer_id} at {addr}: {err}");
        }
    }
}
