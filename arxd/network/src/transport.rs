// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use libp2p::allow_block_list::{self, BlockedPeers};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::request_response::{self, ProtocolSupport, cbor};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{PeerId, StreamProtocol, gossipsub, identify, mdns, noise, tcp, yamux};

use crate::sync::sync_protocol;

/// `identify`'s own wire protocol (`/ipfs/id/1.0.0`) is fixed and un-scoped —
/// unlike `sync_protocol`/gossip topics, two peers on different chains still
/// negotiate it and exchange this string, which is the whole point: it's the
/// one channel that runs *before* any chain-scoped protocol would even have a
/// chance to fail, so a genesis mismatch can be caught and the peer banned
/// immediately instead of just silently never syncing.
pub(crate) fn identify_protocol_version(chain_id: &str) -> String {
    format!("/arxium/id/1/{chain_id}")
}

/// gossipsub's own default (`65536` bytes) is close enough to this chain's
/// worst-case block size (100 actions/block, and the larger action variants
/// carry a ZK proof or BLS pubkey) that a legitimately full block risks being
/// silently dropped from gossip rather than erroring. Set explicitly with
/// real headroom instead of relying on the tight default — 1 MiB is in line
/// with other chains' gossip caps (e.g. Cosmos ~4 MiB, Ethereum consensus
/// 10 MiB) while still bounding message size against abuse.
const MAX_GOSSIP_TRANSMIT_SIZE: usize = 1024 * 1024;

/// Combined behaviour for this node. mDNS handles same-LAN discovery; gossipsub
/// carries Actions between peers. An explicit `--bootnodes` list is dialed
/// directly on startup instead of going through a behaviour, and a real DHT
/// (Kademlia) isn't worth it until the validator set outgrows a
/// hand-maintained list.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
pub(crate) struct Behaviour {
    pub(crate) mdns: mdns::tokio::Behaviour,
    pub(crate) gossipsub: gossipsub::Behaviour,
    /// Carries `SyncRequest`/`SyncResponse<P>` bytes (bincode, encoded and
    /// decoded by `run_swarm` — this behaviour itself just moves opaque
    /// bytes, same as gossipsub does for actions/blocks).
    pub(crate) sync: cbor::Behaviour<Vec<u8>, Vec<u8>>,
    /// Caps connection counts so a burst of dials (malicious or just a noisy
    /// LAN) can't grow unbounded memory/fd usage — see `build_swarm`.
    pub(crate) limits: connection_limits::Behaviour,
    /// Peers banned for unambiguously-bad gossip (see `gossip::record_bad_gossip`).
    /// A hard block at the swarm level, not just a connection drop — a
    /// blocked peer's redial is refused outright instead of getting a fresh
    /// connection to spam on.
    pub(crate) blocked_peers: allow_block_list::Behaviour<BlockedPeers>,
    /// Exchanges `identify_protocol_version(chain_id)` with every peer as
    /// soon as a connection opens — the one channel that runs before any
    /// chain-scoped protocol (sync, gossip) would, so a peer on a different
    /// chain can be caught and banned immediately instead of just quietly
    /// never syncing or gossiping. See `run_swarm`'s `Identify::Received` arm.
    pub(crate) identify: identify::Behaviour,
}

pub(crate) fn build_swarm(
    keypair: libp2p::identity::Keypair,
    chain_id: &str,
) -> Result<libp2p::Swarm<Behaviour>> {
    let local_peer_id = PeerId::from(keypair.public());
    let sync_protocol = StreamProtocol::try_from_owned(sync_protocol(chain_id))
        .map_err(|e| anyhow::anyhow!("invalid chain id for sync protocol: {e}"))?;
    let identify_protocol_version = identify_protocol_version(chain_id);
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|keypair| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .max_transmit_size(MAX_GOSSIP_TRANSMIT_SIZE)
                .build()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let sync = cbor::Behaviour::new(
                [(sync_protocol, ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            // ponytail: fixed caps sized for a devnet's handful of peers;
            // revisit if a real deployment needs more concurrent peers than
            // this. per-peer allows a few (mdns reports one entry per
            // transport, so a single peer legitimately holds >1 connection).
            let limits = connection_limits::Behaviour::new(
                ConnectionLimits::default()
                    .with_max_established_per_peer(Some(4))
                    .with_max_established_incoming(Some(200))
                    .with_max_pending_incoming(Some(100)),
            );
            let identify = identify::Behaviour::new(
                identify::Config::new(identify_protocol_version, keypair.public())
                    .with_agent_version("arxium-node".to_string()),
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Behaviour {
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
                gossipsub,
                sync,
                limits,
                blocked_peers: allow_block_list::Behaviour::default(),
                identify,
            })
        })?
        .build();
    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::identify_protocol_version;

    #[test]
    fn different_chains_get_different_identify_protocol_versions() {
        assert_ne!(identify_protocol_version("chain-a"), identify_protocol_version("chain-b"));
    }

    #[test]
    fn the_same_chain_id_is_stable() {
        assert_eq!(identify_protocol_version("devnet"), identify_protocol_version("devnet"));
    }
}
