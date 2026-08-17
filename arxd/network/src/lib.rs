pub mod identity;

pub use libp2p::PeerId;

use anyhow::{Context, Result};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport, cbor};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{StreamProtocol, gossipsub, mdns, noise, tcp, yamux, Multiaddr};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{info, warn};
use finality::PrecommitVote;
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
/// One pub/sub topic for BLS precommit votes (`finality::PrecommitVote`) —
/// same "gossip is just another untrusted entry point" rule as actions;
/// signature/voter/quorum validation happens in `arxd/finality`, not here.
const PRECOMMITS_TOPIC: &str = "arxium/precommits/v1";
/// Request/response protocol a node uses to catch up on blocks it missed
/// (e.g. was offline for) instead of only ever hearing about the newest
/// block over gossip. Same acceptance path as gossiped blocks — this only
/// adds a second delivery mechanism, not new validation.
const SYNC_PROTOCOL: &str = "/arxium/sync/1";
/// How often a connected peer is re-asked for its tip, to catch a peer
/// falling behind mid-connection (not just "was offline, just reconnected") —
/// e.g. a gossiped block silently dropped rather than erroring, which the
/// OutboundFailure retry above can't see. Kept a small multiple of a
/// devnet-scale block interval (~2s) rather than a long fixed value, so a
/// missed block self-heals in a couple of block times, not tens of seconds.
const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// A peer whose sync requests fail this many times in a row (without a
/// success in between) stops being retried until it reconnects — a flapping
/// connection otherwise retries every single failure immediately, which on a
/// bad link produces dozens of retries per second forever. Past this cap the
/// peer is just skipped by the `STATUS_INTERVAL` tick; `ConnectionEstablished`
/// (a real reconnect) or any successful sync response clears the count.
const MAX_CONSECUTIVE_SYNC_FAILURES: u32 = 5;

/// A peer sending this many unambiguously-bad gossip messages (undecodable
/// bytes, forged signatures) in a row gets disconnected — see
/// `record_bad_gossip`.
const MAX_BAD_GOSSIP: u32 = 10;

/// `Blocks` returns at most `xc_storage::MAX_PAGE_SIZE` blocks starting at
/// `from`, capped at the local tip — never fabricates blocks the responder
/// doesn't have. A node many blocks behind just takes multiple rounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum SyncRequest {
    Status,
    Blocks { from: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum SyncResponse<P> {
    Status { tip_height: u64 },
    Blocks(Vec<Block<P>>),
}

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
    /// Carries `SyncRequest`/`SyncResponse<P>` bytes (bincode, encoded and
    /// decoded by `run_swarm` — this behaviour itself just moves opaque
    /// bytes, same as gossipsub does for actions/blocks).
    sync: cbor::Behaviour<Vec<u8>, Vec<u8>>,
    /// Caps connection counts so a burst of dials (malicious or just a noisy
    /// LAN) can't grow unbounded memory/fd usage — see `build_swarm`.
    limits: connection_limits::Behaviour,
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
    precommit_rx: tokio_mpsc::UnboundedReceiver<PrecommitVote>,
    // Returns `true` when the block's signature itself was forged, so the
    // sending peer can be penalized — see `record_bad_gossip`.
    on_block: impl Fn(Block<P>) -> bool + Send + 'static,
    // Undecodable-bytes handling only — `arxd/finality` owns signature and
    // quorum validation, this crate just moves the bytes.
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
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
            keypair, listen_port, bootnodes, mempool, db, gossip_rx, block_rx, precommit_rx,
            on_block, on_precommit_vote, ready_tx,
        ));
    });

    ready_rx
        .recv()
        .context("p2p thread exited before signaling readiness")??;

    Ok(peer_id)
}

fn local_tip_height(db: &ArxiumDb) -> u64 {
    db.get_tip_height().ok().flatten().unwrap_or(0)
}

fn send_sync_request(swarm: &mut libp2p::Swarm<Behaviour>, peer: &PeerId, request: &SyncRequest) {
    match bincode::serde::encode_to_vec(request, bincode::config::standard()) {
        Ok(bytes) => {
            swarm.behaviour_mut().sync.send_request(peer, bytes);
        }
        Err(err) => warn!("failed to encode sync request: {err}"),
    }
}

/// Records gossip that's unambiguously bad — undecodable bytes or a forged
/// signature, never just "this peer is a bit behind" — and disconnects the
/// peer once it crosses `MAX_BAD_GOSSIP`, so a hostile peer can't spam
/// garbage at zero cost forever. `ConnectionEstablished` clears the count on
/// reconnect, same as `sync_failures`.
fn record_bad_gossip(
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

async fn run_swarm<P: Payload>(
    keypair: libp2p::identity::Keypair,
    listen_port: u16,
    bootnodes: Vec<Multiaddr>,
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    mut gossip_rx: tokio_mpsc::UnboundedReceiver<Action<P>>,
    mut block_rx: tokio_mpsc::UnboundedReceiver<Block<P>>,
    mut precommit_rx: tokio_mpsc::UnboundedReceiver<PrecommitVote>,
    on_block: impl Fn(Block<P>) -> bool + Send + 'static,
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
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
    let precommits_topic = gossipsub::IdentTopic::new(PRECOMMITS_TOPIC);
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&precommits_topic) {
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

    // Tracks each peer's last-reported tip height, so a `Blocks` response
    // knows whether to request the next batch or stop — set on every
    // `Status` response, both the on-connect one and the periodic re-check.
    let mut peer_tips: HashMap<PeerId, u64> = HashMap::new();
    // Consecutive sync-request failures per peer since its last success or
    // reconnect — see `MAX_CONSECUTIVE_SYNC_FAILURES`.
    let mut sync_failures: HashMap<PeerId, u32> = HashMap::new();
    // Consecutive unambiguously-bad gossip messages per peer — see
    // `record_bad_gossip`.
    let mut bad_gossip: HashMap<PeerId, u32> = HashMap::new();
    let mut status_interval = tokio::time::interval(STATUS_INTERVAL);

    loop {
        tokio::select! {
            _ = status_interval.tick() => {
                let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                metrics::gauge!("arxium_connected_peers").set(peers.len() as f64);
                for peer in peers {
                    if sync_failures.get(&peer).is_some_and(|&n| n >= MAX_CONSECUTIVE_SYNC_FAILURES) {
                        continue;
                    }
                    send_sync_request(&mut swarm, &peer, &SyncRequest::Status);
                }
            }
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
            vote = precommit_rx.recv() => {
                let Some(vote) = vote else {
                    // Sender side (finality subsystem) is gone — nothing left to publish.
                    continue;
                };
                match bincode::serde::encode_to_vec(&vote, bincode::config::standard()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(precommits_topic.clone(), bytes) {
                            warn!("failed to publish precommit vote to gossip: {err}");
                        }
                    }
                    Err(err) => warn!("failed to encode precommit vote for gossip: {err}"),
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
                    // Fresh connection — give it a clean slate rather than
                    // carrying over failures accrued before it dropped.
                    sync_failures.remove(&peer_id);
                    bad_gossip.remove(&peer_id);
                    // Ask immediately — a node that was offline and just
                    // reconnected shouldn't have to wait for the next
                    // STATUS_INTERVAL tick to start catching up.
                    send_sync_request(&mut swarm, &peer_id, &SyncRequest::Status);
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
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                &format!("undecodable gossiped action: {err}"),
                            );
                            continue;
                        }
                    };

                    // Gossip is just another untrusted input source — no more
                    // trusted than a stranger hitting RPC directly, so it runs
                    // through the exact same admission check.
                    if let Err(err) = validate_action(&db, &action) {
                        // A bad signature can't be innocent lag — it's forged
                        // or corrupted. Stale-nonce/storage rejects are just
                        // an honest peer relaying something already applied,
                        // not counted against them.
                        if matches!(err, xc_mempool::AdmissionError::BadSignature(_)) {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                &format!("forged gossiped action: {err}"),
                            );
                        } else {
                            warn!("rejected gossiped action from {propagation_source}: {err}");
                        }
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
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                &format!("undecodable gossiped block: {err}"),
                            );
                            continue;
                        }
                    };
                    if on_block(block) {
                        record_bad_gossip(
                            &mut swarm,
                            &mut bad_gossip,
                            propagation_source,
                            "forged gossiped block signature",
                        );
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == precommits_topic.hash() => {
                    let vote: PrecommitVote = match bincode::serde::decode_from_slice(
                        &message.data,
                        bincode::config::standard(),
                    ) {
                        Ok((vote, _)) => vote,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                &format!("undecodable gossiped precommit vote: {err}"),
                            );
                            continue;
                        }
                    };
                    on_precommit_vote(vote);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::OutboundFailure {
                    peer,
                    error,
                    ..
                })) => {
                    // Don't retry synchronously — on a flapping connection
                    // each failure re-triggers another immediately, which
                    // spins into a flood of retries per second. Record the
                    // failure and let the next STATUS_INTERVAL tick (or a
                    // fresh ConnectionEstablished) retry instead — a real
                    // backoff, not a tight loop. Past
                    // MAX_CONSECUTIVE_SYNC_FAILURES the tick skips this peer
                    // entirely until it reconnects or a request succeeds.
                    let failures = sync_failures.entry(peer).or_insert(0);
                    *failures += 1;
                    if *failures >= MAX_CONSECUTIVE_SYNC_FAILURES {
                        warn!(
                            "sync request to {peer} failed: {error} ({failures} consecutive failures, giving up until it reconnects)"
                        );
                    } else if swarm.is_connected(&peer) {
                        warn!(
                            "sync request to {peer} failed: {error} (will retry on next status interval)"
                        );
                    } else {
                        warn!(
                            "sync request to {peer} failed: {error} (not connected, will retry on reconnect)"
                        );
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::InboundFailure {
                    peer,
                    error,
                    ..
                })) => {
                    warn!("failed to answer sync request from {peer}: {error}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::Message {
                    peer,
                    message,
                    ..
                })) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let sync_request: SyncRequest = match bincode::serde::decode_from_slice(
                            &request,
                            bincode::config::standard(),
                        ) {
                            Ok((req, _)) => req,
                            Err(err) => {
                                warn!("failed to decode sync request from {peer}: {err}");
                                continue;
                            }
                        };
                        let response = match sync_request {
                            SyncRequest::Status => SyncResponse::<P>::Status {
                                tip_height: local_tip_height(&db),
                            },
                            SyncRequest::Blocks { from } => {
                                let tip_height = local_tip_height(&db);
                                let blocks = db
                                    .get_block_range::<P>(from, tip_height)
                                    .unwrap_or_else(|err| {
                                        warn!(
                                            "failed to read blocks {from}..={tip_height} for sync response to {peer}: {err}"
                                        );
                                        Vec::new()
                                    });
                                SyncResponse::Blocks(blocks)
                            }
                        };
                        match bincode::serde::encode_to_vec(&response, bincode::config::standard()) {
                            Ok(bytes) => {
                                if swarm.behaviour_mut().sync.send_response(channel, bytes).is_err() {
                                    warn!("failed to send sync response to {peer}: channel closed");
                                }
                            }
                            Err(err) => warn!("failed to encode sync response for {peer}: {err}"),
                        }
                    }
                    request_response::Message::Response { response, .. } => {
                        let sync_response: SyncResponse<P> = match bincode::serde::decode_from_slice(
                            &response,
                            bincode::config::standard(),
                        ) {
                            Ok((resp, _)) => resp,
                            Err(err) => {
                                warn!("failed to decode sync response from {peer}: {err}");
                                continue;
                            }
                        };
                        // A response means the peer is reachable again —
                        // don't leave it skipped by a stale failure count.
                        sync_failures.remove(&peer);
                        match sync_response {
                            SyncResponse::Status { tip_height } => {
                                peer_tips.insert(peer, tip_height);
                                let local_tip = local_tip_height(&db);
                                if tip_height > local_tip {
                                    info!(
                                        "peer {peer} is ahead (tip {tip_height} vs local {local_tip}), requesting sync"
                                    );
                                    send_sync_request(&mut swarm, &peer, &SyncRequest::Blocks {
                                        from: local_tip + 1,
                                    });
                                }
                            }
                            SyncResponse::Blocks(blocks) => {
                                if blocks.is_empty() {
                                    continue;
                                }
                                // Same acceptance path as a gossiped block —
                                // sync is only a second delivery mechanism,
                                // not new validation logic.
                                for block in blocks {
                                    if on_block(block) {
                                        record_bad_gossip(
                                            &mut swarm,
                                            &mut bad_gossip,
                                            peer,
                                            "forged synced block signature",
                                        );
                                    }
                                }
                                let local_tip = local_tip_height(&db);
                                if peer_tips.get(&peer).is_some_and(|&tip| tip > local_tip) {
                                    send_sync_request(&mut swarm, &peer, &SyncRequest::Blocks {
                                        from: local_tip + 1,
                                    });
                                }
                            }
                        }
                    }
                },
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
        let (_precommit_tx, precommit_rx) = tokio_mpsc::unbounded_channel();

        let peer_id = spawn_p2p_node(
            &base_path, 0, &[], false, mempool, db, gossip_rx, block_rx, precommit_rx, |_| false,
            |_| {},
        )
        .expect("node should start on OS-assigned port");
        assert!(!peer_id.to_string().is_empty());

        std::fs::remove_dir_all(&base_path).ok();
    }
}
