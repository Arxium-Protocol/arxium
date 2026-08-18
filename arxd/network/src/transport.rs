use anyhow::Result;
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::request_response::{self, ProtocolSupport, cbor};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{PeerId, StreamProtocol, gossipsub, mdns, noise, tcp, yamux};

use crate::sync::SYNC_PROTOCOL;

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
}

pub(crate) fn build_swarm(keypair: libp2p::identity::Keypair) -> Result<libp2p::Swarm<Behaviour>> {
    let local_peer_id = PeerId::from(keypair.public());
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|keypair| {
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub::Config::default(),
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let sync = cbor::Behaviour::new(
                [(StreamProtocol::new(SYNC_PROTOCOL), ProtocolSupport::Full)],
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
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Behaviour {
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
                gossipsub,
                sync,
                limits,
            })
        })?
        .build();
    Ok(swarm)
}
