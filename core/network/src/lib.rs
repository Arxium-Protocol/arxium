mod identity;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, mdns, noise, tcp, yamux, Multiaddr, PeerId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{info, warn};
use xc_mempool::{Mempool, validate_action};
use xc_primitives::{Action, Block};
use xc_storage::ArxiumDb;

/// Bound the chain's payload type must satisfy to travel over gossip:
/// bincode (de)serializable for the wire, `Send + Sync + 'static` to cross
/// into the swarm's own thread.
pub trait Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> Payload for P {}

/// One pub/sub topic for actions — gossip is just another untrusted entry
/// point into the mempool, no more trusted than a stranger hitting RPC.
const ACTIONS_TOPIC: &str = "arxium/actions/v1";
/// One pub/sub topic for blocks. Validation (signature, expected proposer,
/// parent hash) happens in the caller-supplied `on_block` callback — this
/// crate doesn't know how to execute a chain's actions, only how to move
/// bytes between peers.
const BLOCKS_TOPIC: &str = "arxium/blocks/v1";

/// Combined behaviour for this node. mDNS handles same-LAN discovery; gossipsub
/// carries Actions between peers. An explicit `--bootnodes` list is dialed
/// directly on startup instead of going through a behaviour, and a real DHT
/// (Kademlia) isn't worth it until the validator set outgrows a
/// hand-maintained list.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct Behaviour {
    mdns: mdns::tokio::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

/// Starts this node's P2P identity, listeners, peer discovery, and Action +
/// Block gossip on a dedicated thread with its own tokio runtime — same
/// shape as `xc_rpc::spawn_http_ingest`, kept separate from the node's
/// synchronous block-production loop.
///
/// Discovery is mDNS (same-LAN) plus dialing `bootnodes` explicitly; no DHT.
/// Actions received on `gossip_rx` (e.g. freshly admitted via RPC) are
/// published to the actions topic; actions received from peers over that
/// topic are run through `xc_mempool::validate_action` — the same admission
/// check RPC submissions get — before landing in `mempool`. Blocks received
/// on `block_rx` (e.g. freshly produced locally) are published to the
/// blocks topic; blocks received from peers are handed to `on_block`
/// unvalidated — this crate has no idea what a chain's actions mean, so all
/// verification and application is the caller's job. Returns once the
/// listeners are registered, so the caller finds out synchronously if the
/// port is unusable.
pub fn spawn_p2p_node<P: Payload>(
    base_path: &Path,
    listen_port: u16,
    bootnodes: &[String],
    is_bootnode: bool,
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    gossip_rx: tokio_mpsc::UnboundedReceiver<Action<P>>,
    block_rx: tokio_mpsc::UnboundedReceiver<Block<P>>,
    on_block: impl Fn(Block<P>) + Send + 'static,
) -> Result<PeerId> {
    let keypair = if is_bootnode {
        identity::load_or_generate_devnet_bootnode_keypair(base_path)?
    } else {
        identity::load_or_generate_keypair(base_path)?
    };
    let peer_id = PeerId::from(keypair.public());
    info!("p2p identity: {peer_id}");

    let bootnodes = bootnodes
        .iter()
        .filter(|addr| !addr.is_empty())
        .map(|addr| {
            addr.parse::<Multiaddr>()
                .with_context(|| format!("invalid bootnode multiaddr: {addr}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                let _ = ready_tx.send(Err(err.into()));
                return;
            }
        };

        runtime.block_on(run_swarm(
            keypair, listen_port, bootnodes, mempool, db, gossip_rx, block_rx, on_block, ready_tx,
        ));
    });

    ready_rx
        .recv()
        .context("p2p thread exited before signaling readiness")??;

    Ok(peer_id)
}

fn build_swarm(keypair: libp2p::identity::Keypair) -> Result<libp2p::Swarm<Behaviour>> {
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
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Behaviour {
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
                gossipsub,
            })
        })?
        .build();
    Ok(swarm)
}

async fn run_swarm<P: Payload>(
    keypair: libp2p::identity::Keypair,
    listen_port: u16,
    bootnodes: Vec<Multiaddr>,
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    mut gossip_rx: tokio_mpsc::UnboundedReceiver<Action<P>>,
    mut block_rx: tokio_mpsc::UnboundedReceiver<Block<P>>,
    on_block: impl Fn(Block<P>) + Send + 'static,
    ready_tx: std_mpsc::Sender<Result<()>>,
) {
    let mut swarm = match build_swarm(keypair) {
        Ok(swarm) => swarm,
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            return;
        }
    };

    let actions_topic = gossipsub::IdentTopic::new(ACTIONS_TOPIC);
    let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&actions_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }

    let listen_result = swarm
        .listen_on(
            format!("/ip4/0.0.0.0/tcp/{listen_port}")
                .parse()
                .expect("valid multiaddr"),
        )
        .and_then(|_| {
            swarm.listen_on(
                format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1")
                    .parse()
                    .expect("valid multiaddr"),
            )
        })
        .map(|_| ())
        .context("failed to start p2p listener");

    let ok = listen_result.is_ok();
    let _ = ready_tx.send(listen_result);
    if !ok {
        return;
    }

    for addr in bootnodes {
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!("failed to dial bootnode {addr}: {err}");
        }
    }

    loop {
        tokio::select! {
            action = gossip_rx.recv() => {
                let Some(action) = action else {
                    // Sender side (RPC ingest) is gone — nothing left to publish.
                    continue;
                };
                match bincode::serde::encode_to_vec(&action, bincode::config::standard()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(actions_topic.clone(), bytes) {
                            warn!("failed to publish action to gossip: {err}");
                        }
                    }
                    Err(err) => warn!("failed to encode action for gossip: {err}"),
                }
            }
            block = block_rx.recv() => {
                let Some(block) = block else {
                    // Sender side (block-production loop) is gone — nothing left to publish.
                    continue;
                };
                match bincode::serde::encode_to_vec(&block, bincode::config::standard()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(blocks_topic.clone(), bytes) {
                            warn!("failed to publish block to gossip: {err}");
                        }
                    }
                    Err(err) => warn!("failed to encode block for gossip: {err}"),
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("p2p listening on {address}");
                }
                SwarmEvent::ListenerError { error, .. } => {
                    warn!("p2p listener error: {error}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    info!("connected to peer {peer_id}");
                }
                // ponytail: mdns reports one entry per transport (tcp + quic),
                // so a discovered peer gets dialed twice and briefly shows two
                // connections. Harmless while nothing beyond gossip messages is
                // exchanged over them; collapse to one dial per peer if that changes.
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                    for (peer_id, addr) in peers {
                        info!("mdns discovered peer {peer_id} at {addr}");
                        if let Err(err) = swarm.dial(addr.clone()) {
                            warn!("failed to dial discovered peer {peer_id} at {addr}: {err}");
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == actions_topic.hash() => {
                    let action: Action<P> = match bincode::serde::decode_from_slice(
                        &message.data,
                        bincode::config::standard(),
                    ) {
                        Ok((action, _)) => action,
                        Err(err) => {
                            warn!("failed to decode gossiped action from {propagation_source}: {err}");
                            continue;
                        }
                    };

                    // Gossip is just another untrusted input source — no more
                    // trusted than a stranger hitting RPC directly, so it runs
                    // through the exact same admission check.
                    if let Err(err) = validate_action(&db, &action) {
                        warn!("rejected gossiped action from {propagation_source}: {err}");
                        continue;
                    }

                    let mut mempool = mempool.lock().unwrap_or_else(|e| e.into_inner());
                    match mempool.push(action) {
                        Ok(()) => info!("admitted gossiped action from {propagation_source}"),
                        Err(xc_mempool::MempoolError::Duplicate { .. }) => {}
                        Err(err) => warn!("failed to queue gossiped action: {err}"),
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == blocks_topic.hash() => {
                    let block: Block<P> = match bincode::serde::decode_from_slice(
                        &message.data,
                        bincode::config::standard(),
                    ) {
                        Ok((block, _)) => block,
                        Err(err) => {
                            warn!("failed to decode gossiped block from {propagation_source}: {err}");
                            continue;
                        }
                    };
                    on_block(block);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawns_and_returns_peer_id() {
        let base_path = std::env::temp_dir().join(format!(
            "arxium-test-network-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base_path).unwrap();

        let mempool = Arc::new(Mutex::new(Mempool::<()>::new()));
        let db = ArxiumDb::open(&base_path.join("data")).unwrap();
        let (_gossip_tx, gossip_rx) = tokio_mpsc::unbounded_channel();
        let (_block_tx, block_rx) = tokio_mpsc::unbounded_channel();

        let peer_id = spawn_p2p_node(&base_path, 0, &[], false, mempool, db, gossip_rx, block_rx, |_| {})
            .expect("node should start on OS-assigned port");
        assert!(!peer_id.to_string().is_empty());

        std::fs::remove_dir_all(&base_path).ok();
    }
}
