// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

pub mod identity;
mod discovery;
mod gossip;
mod recovery;
mod sync;
mod transport;

pub use gossip::Payload;
pub use libp2p::PeerId;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, gossipsub, identify, mdns};
use metrics::counter;
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::thread;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info, warn};

use arxd_finality::{Dissent, PrecommitVote, RoundTimeoutVote, verify_finality_record};
use xc_mempool::{Mempool, PayloadPrecheck, validate_action};
use xc_primitives::{Action, Block};
use xc_storage::{ArxiumDb, FinalityRecord};

use discovery::{dial_bootnodes, dial_discovered};
use recovery::{Recovery, RecoveryStep, allow_revert, first_divergent_height, plan};
use gossip::{
    actions_topic, blocks_topic, dissents_topic, precommits_topic, record_bad_gossip, round_timeouts_topic,
};
use sync::{
    MAX_CONSECUTIVE_SYNC_FAILURES, NodeInfo, STATUS_INTERVAL, SyncRequest, SyncResponse,
    advance_stuck_tip, local_tip_height,
    send_sync_request,
};
use transport::{BehaviourEvent, build_swarm, identify_protocol_version};

/// Decodes an untrusted, peer-supplied byte slice (gossip message or sync
/// payload, always read before any signature check) — bounded by
/// `xc_primitives::MAX_WIRE_MESSAGE_SIZE` so a peer can't force a huge
/// allocation via a declared length, and rejecting trailing bytes so a
/// padded message can't silently round-trip to something other than what
/// arrived on the wire.
fn decode_wire<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError> {
    let (value, consumed) = bincode::serde::decode_from_slice(bytes, xc_primitives::wire_config())?;
    if consumed != bytes.len() {
        return Err(bincode::error::DecodeError::Other("trailing bytes after decoded value"));
    }
    Ok(value)
}

/// A gossip publish can fail because nobody local is subscribed to the
/// topic — expected on a devnet where not every peer subscribes to every
/// topic (e.g. an indexer that only follows blocks), harmless since the
/// message was still accepted and committed locally. Anything else is a
/// real fault.
fn log_publish_error(kind: &str, err: &gossipsub::PublishError) {
    if matches!(err, gossipsub::PublishError::NoPeersSubscribedToTopic) {
        info!("no peers subscribed to receive the gossiped {kind}, skipping");
    } else {
        warn!("failed to publish {kind} to gossip: {err}");
    }
}

/// Starts this node's P2P networking on its own thread with its own tokio
/// runtime (libp2p's swarm isn't `Send` across an existing async runtime the
/// caller might be using). Gossiped/synced messages only get as far as
/// bincode decoding and, for actions, the same admission checks RPC uses —
/// payload-agnostic (`validate_action`) and, if provided, the chain-specific
/// `payload_precheck` — deeper application verification is the caller's
/// job. Returns once the
/// listeners are registered, so the caller finds out synchronously if the
/// port is unusable.
pub fn spawn_p2p_node<P: Payload>(
    base_path: &Path,
    listen_port: u16,
    bootnodes: &[String],
    is_bootnode: bool,
    // Short hex identifier for the chain this node runs (e.g. the genesis
    // hash) — gossip topic names are suffixed with this, so nodes on
    // different chains never subscribe to each other's topics in the first
    // place. Any two callers who want to gossip with each other must pass
    // the same string.
    chain_id: &str,
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    gossip_rx: tokio_mpsc::UnboundedReceiver<Action<P>>,
    block_rx: tokio_mpsc::UnboundedReceiver<Block<P>>,
    precommit_rx: tokio_mpsc::UnboundedReceiver<PrecommitVote>,
    dissent_rx: tokio_mpsc::UnboundedReceiver<Dissent>,
    round_timeout_rx: tokio_mpsc::UnboundedReceiver<RoundTimeoutVote>,
    // Returns `true` if the block's signature is itself forged, so the
    // sending peer can be penalized — see `record_bad_gossip`. Second
    // argument is `sync`: true when applying a `SyncRequest::Blocks` page
    // during catch-up (fsync deferred to one `flush_wal` per page below),
    // false for a single gossiped block (fsync immediately).
    on_block: impl Fn(Block<P>, bool) -> bool + Send + 'static,
    // Undecodable-bytes handling only — `arxd/finality` owns signature and
    // quorum validation, this crate just moves bytes.
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
    // Same "undecodable bytes only" rule as `on_precommit_vote` — `arxd/finality`
    // owns signature/voter/one-per-height validation for dissents too.
    on_dissent: impl Fn(Dissent) + Send + 'static,
    // Same "undecodable bytes only" rule — `arxd/finality` owns
    // signature/voter/quorum validation for round-timeout votes too.
    on_round_timeout_vote: impl Fn(RoundTimeoutVote) + Send + 'static,
    // Same chain-specific admission hook RPC submission runs — see
    // `xc_mempool::PayloadPrecheck` doc comment. `None` for chains with no
    // such rules.
    payload_precheck: Option<PayloadPrecheck<P>>,
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
    let chain_id = chain_id.to_string();

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
            keypair, listen_port, bootnodes, &chain_id, mempool, db, gossip_rx, block_rx, precommit_rx,
            dissent_rx, round_timeout_rx, on_block, on_precommit_vote, on_dissent, on_round_timeout_vote,
            payload_precheck, ready_tx,
        ));
    });

    ready_rx
        .recv()
        .context("p2p thread exited before signaling readiness")??;

    Ok(peer_id)
}

async fn run_swarm<P: Payload>(
    keypair: libp2p::identity::Keypair,
    listen_port: u16,
    bootnodes: Vec<Multiaddr>,
    chain_id: &str,
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    mut gossip_rx: tokio_mpsc::UnboundedReceiver<Action<P>>,
    mut block_rx: tokio_mpsc::UnboundedReceiver<Block<P>>,
    mut precommit_rx: tokio_mpsc::UnboundedReceiver<PrecommitVote>,
    mut dissent_rx: tokio_mpsc::UnboundedReceiver<Dissent>,
    mut round_timeout_rx: tokio_mpsc::UnboundedReceiver<RoundTimeoutVote>,
    on_block: impl Fn(Block<P>, bool) -> bool + Send + 'static,
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
    on_dissent: impl Fn(Dissent) + Send + 'static,
    on_round_timeout_vote: impl Fn(RoundTimeoutVote) + Send + 'static,
    payload_precheck: Option<PayloadPrecheck<P>>,
    ready_tx: std_mpsc::Sender<Result<()>>,
) {
    let mut swarm = match build_swarm(keypair, chain_id) {
        Ok(swarm) => swarm,
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            return;
        }
    };

    let expected_identify_protocol = identify_protocol_version(chain_id);

    let actions_topic = gossipsub::IdentTopic::new(actions_topic(chain_id));
    let blocks_topic = gossipsub::IdentTopic::new(blocks_topic(chain_id));
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&actions_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }
    let precommits_topic = gossipsub::IdentTopic::new(precommits_topic(chain_id));
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&precommits_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }
    let dissents_topic = gossipsub::IdentTopic::new(dissents_topic(chain_id));
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&dissents_topic) {
        let _ = ready_tx.send(Err(err.into()));
        return;
    }
    let round_timeouts_topic = gossipsub::IdentTopic::new(round_timeouts_topic(chain_id));
    if let Err(err) = swarm.behaviour_mut().gossipsub.subscribe(&round_timeouts_topic) {
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

    dial_bootnodes(&mut swarm, bootnodes);

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
    // Tracks (height, consecutive rounds without progress) so a sync loop
    // that keeps re-fetching the same block(s) `on_block` keeps rejecting
    // (state genuinely diverged from this peer) logs once loudly instead of
    // an unbounded `warn!` every `STATUS_INTERVAL` forever — and now also
    // triggers divergence recovery once, at the cap. See `recovery`.
    let mut stuck_tip: Option<(u64, u32)> = None;
    // Peers whose `Hashes`/`Certificate` responses this node actually asked
    // for, as part of divergence recovery. An unsolicited one is still
    // ignored — a peer must not be able to start a rollback conversation this
    // node didn't open.
    let mut recovering: HashMap<PeerId, RecoveryStep> = HashMap::new();
    // When the last automatic revert happened — see `recovery::REVERT_COOLDOWN`.
    let mut last_revert: Option<Instant> = None;
    // Latched once this node learns, from a certificate it verified itself,
    // that it committed to something the network certified against below its
    // own watermark. Recovery never runs again after that: the state is
    // preserved as-is for forensics rather than reshaped.
    let mut halted_below_watermark = false;

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
                match bincode::serde::encode_to_vec(&action, xc_primitives::wire_config()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(actions_topic.clone(), bytes) {
                            log_publish_error("action", &err);
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
                match bincode::serde::encode_to_vec(&block, xc_primitives::wire_config()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(blocks_topic.clone(), bytes) {
                            log_publish_error("block", &err);
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
                match bincode::serde::encode_to_vec(&vote, xc_primitives::wire_config()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(precommits_topic.clone(), bytes) {
                            log_publish_error("precommit vote", &err);
                        }
                    }
                    Err(err) => warn!("failed to encode precommit vote for gossip: {err}"),
                }
            }
            dissent = dissent_rx.recv() => {
                let Some(dissent) = dissent else {
                    // Sender side (finality/node subsystem) is gone — nothing left to publish.
                    continue;
                };
                match bincode::serde::encode_to_vec(&dissent, xc_primitives::wire_config()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(dissents_topic.clone(), bytes) {
                            log_publish_error("dissent", &err);
                        }
                    }
                    Err(err) => warn!("failed to encode dissent for gossip: {err}"),
                }
            }
            round_timeout_vote = round_timeout_rx.recv() => {
                let Some(round_timeout_vote) = round_timeout_vote else {
                    // Sender side (finality subsystem) is gone — nothing left to publish.
                    continue;
                };
                match bincode::serde::encode_to_vec(&round_timeout_vote, xc_primitives::wire_config()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(round_timeouts_topic.clone(), bytes) {
                            log_publish_error("round-timeout vote", &err);
                        }
                    }
                    Err(err) => warn!("failed to encode round-timeout vote for gossip: {err}"),
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
                    // Fresh connection — give it a clean slate for sync
                    // failures (honest transient network issues). Bad-gossip
                    // counts deliberately do NOT reset here — see
                    // `gossip::record_bad_gossip`.
                    sync_failures.remove(&peer_id);
                    // Ask immediately — a node that was offline and just
                    // reconnected shouldn't have to wait for the next
                    // STATUS_INTERVAL tick to start catching up.
                    send_sync_request(&mut swarm, &peer_id, &SyncRequest::Status);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                    dial_discovered(&mut swarm, peers);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    // Unlike bad gossip (which gets a strike counter — a
                    // burst of malformed messages can be transient), a
                    // genesis mismatch is unambiguous: this peer is
                    // permanently on a different chain, not just
                    // temporarily confused. One strike.
                    if info.protocol_version != expected_identify_protocol {
                        warn!(
                            "banning {peer_id}: genesis mismatch (peer speaks {:?}, we speak {expected_identify_protocol:?})",
                            info.protocol_version
                        );
                        swarm.behaviour_mut().blocked_peers.block_peer(peer_id);
                        counter!("arxium_genesis_mismatch_peers_banned_total").increment(1);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == actions_topic.hash() => {
                    let action: Action<P> = match decode_wire(&message.data) {
                        Ok(action) => action,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                "actions",
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
                                "actions",
                                &format!("forged gossiped action: {err}"),
                            );
                        } else {
                            counter!("arxium_gossip_rejected_total", "topic" => "actions", "reason" => "stale").increment(1);
                            warn!("rejected gossiped action from {propagation_source}: {err}");
                        }
                        continue;
                    }

                    if let Some(precheck) = &payload_precheck {
                        if let Err(err) = precheck(&action, &db) {
                            counter!("arxium_gossip_rejected_total", "topic" => "actions", "reason" => "stale").increment(1);
                            warn!("rejected gossiped action from {propagation_source}: {err}");
                            continue;
                        }
                    }

                    let mut mempool = mempool.lock().unwrap_or_else(|e| e.into_inner());
                    match mempool.push(action) {
                        Ok(()) => {
                            counter!("arxium_gossip_accepted_total", "topic" => "actions").increment(1);
                            info!("admitted gossiped action from {propagation_source}");
                        }
                        Err(xc_mempool::MempoolError::Duplicate { .. }) => {}
                        Err(err @ xc_mempool::MempoolError::TooLarge { .. }) => {
                            counter!("arxium_mempool_rejected_oversized_total").increment(1);
                            warn!("failed to queue gossiped action: {err}");
                        }
                        Err(err) => warn!("failed to queue gossiped action: {err}"),
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == blocks_topic.hash() => {
                    let block: Block<P> = match decode_wire(&message.data) {
                        Ok(block) => block,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                "blocks",
                                &format!("undecodable gossiped block: {err}"),
                            );
                            continue;
                        }
                    };
                    if on_block(block, false) {
                        record_bad_gossip(
                            &mut swarm,
                            &mut bad_gossip,
                            propagation_source,
                            "blocks",
                            "forged gossiped block signature",
                        );
                    } else {
                        counter!("arxium_gossip_accepted_total", "topic" => "blocks").increment(1);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == precommits_topic.hash() => {
                    let vote: PrecommitVote = match decode_wire(&message.data) {
                        Ok(vote) => vote,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                "precommits",
                                &format!("undecodable gossiped precommit vote: {err}"),
                            );
                            continue;
                        }
                    };
                    counter!("arxium_gossip_accepted_total", "topic" => "precommits").increment(1);
                    on_precommit_vote(vote);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == dissents_topic.hash() => {
                    let dissent: Dissent = match decode_wire(&message.data) {
                        Ok(dissent) => dissent,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                "dissents",
                                &format!("undecodable gossiped dissent: {err}"),
                            );
                            continue;
                        }
                    };
                    counter!("arxium_gossip_accepted_total", "topic" => "dissents").increment(1);
                    on_dissent(dissent);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                })) if message.topic == round_timeouts_topic.hash() => {
                    let vote: RoundTimeoutVote = match decode_wire(&message.data) {
                        Ok(vote) => vote,
                        Err(err) => {
                            record_bad_gossip(
                                &mut swarm,
                                &mut bad_gossip,
                                propagation_source,
                                "round_timeouts",
                                &format!("undecodable gossiped round-timeout vote: {err}"),
                            );
                            continue;
                        }
                    };
                    counter!("arxium_gossip_accepted_total", "topic" => "round_timeouts").increment(1);
                    on_round_timeout_vote(vote);
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
                    counter!("arxium_sync_outbound_failures_total").increment(1);
                    let failures = sync_failures.entry(peer).or_insert(0);
                    if matches!(error, request_response::OutboundFailure::UnsupportedProtocols) {
                        // A peer capability, not a transient fault (e.g. the
                        // indexer, which only serves sync inbound) — retrying
                        // on the next STATUS_INTERVAL can't change the
                        // outcome, so skip straight to "give up until
                        // reconnect" instead of warn-spamming every tick
                        // until the counter ramps up on its own.
                        *failures = MAX_CONSECUTIVE_SYNC_FAILURES;
                        info!("peer {peer} does not support the sync protocol, will not retry until it reconnects");
                    } else if { *failures += 1; *failures >= MAX_CONSECUTIVE_SYNC_FAILURES } {
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
                    counter!("arxium_sync_inbound_failures_total").increment(1);
                    warn!("failed to answer sync request from {peer}: {error}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::Message {
                    peer,
                    message,
                    ..
                })) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let sync_request: SyncRequest = match decode_wire(&request) {
                            Ok(req) => req,
                            Err(err) => {
                                warn!("failed to decode sync request from {peer}: {err}");
                                continue;
                            }
                        };
                        let response = match sync_request {
                            SyncRequest::Status => SyncResponse::<Block<P>>::Status {
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
                            // Everything a follower would otherwise have to
                            // hardcode or guess: the page size it must match,
                            // how far finality has actually got, and which
                            // wire generation we speak.
                            SyncRequest::NodeInfo => {
                                let tip_height = local_tip_height(&db);
                                let tip_hash = db
                                    .get_block_range::<P>(tip_height, tip_height)
                                    .ok()
                                    .and_then(|blocks| blocks.first().map(|b| b.hash()));
                                SyncResponse::<Block<P>>::NodeInfo(NodeInfo {
                                    wire_version: xc_wire::WIRE_VERSION,
                                    tip_height,
                                    tip_hash,
                                    finalized_height: db
                                        .get_finalized_height()
                                        .unwrap_or_else(|err| {
                                            warn!("failed to read finalized height: {err}");
                                            None
                                        }),
                                    max_page_size: xc_storage::MAX_PAGE_SIZE as u32,
                                })
                            }
                            // Hashes without bodies, so a follower resolving a
                            // fork can binary-search for the common ancestor
                            // instead of downloading one block per round trip.
                            SyncRequest::Hashes { from, to } => {
                                let to = to.min(local_tip_height(&db));
                                let hashes = db
                                    .get_block_range::<P>(from, to)
                                    .unwrap_or_else(|err| {
                                        warn!(
                                            "failed to read blocks {from}..={to} for hash response to {peer}: {err}"
                                        );
                                        Vec::new()
                                    })
                                    .into_iter()
                                    .map(|block| (block.height, block.hash()))
                                    .collect();
                                SyncResponse::<Block<P>>::Hashes(hashes)
                            }
                            // Serving this is what lets a diverged peer check
                            // our claim instead of taking it on faith — see
                            // `recovery`.
                            SyncRequest::Certificate { height } => {
                                let record = db
                                    .get_finality_record(height)
                                    .unwrap_or_else(|err| {
                                        warn!("failed to read finality record at {height} for {peer}: {err}");
                                        None
                                    })
                                    .and_then(|record| {
                                        bincode::serde::encode_to_vec(&record, xc_primitives::wire_config())
                                            .map_err(|err| warn!("failed to encode finality record at {height}: {err}"))
                                            .ok()
                                    });
                                SyncResponse::<Block<P>>::Certificate { height, record }
                            }
                        };
                        match bincode::serde::encode_to_vec(&response, xc_primitives::wire_config()) {
                            Ok(bytes) => {
                                if swarm.behaviour_mut().sync.send_response(channel, bytes).is_err() {
                                    warn!("failed to send sync response to {peer}: channel closed");
                                }
                            }
                            Err(err) => warn!("failed to encode sync response for {peer}: {err}"),
                        }
                    }
                    request_response::Message::Response { response, .. } => {
                        let sync_response: SyncResponse<Block<P>> = match decode_wire(&response) {
                            Ok(resp) => resp,
                            Err(err) => {
                                warn!("failed to decode sync response from {peer}: {err}");
                                continue;
                            }
                        };
                        // A response means the peer is reachable again —
                        // don't leave it skipped by a stale failure count.
                        sync_failures.remove(&peer);
                        let kind = match &sync_response {
                            SyncResponse::Status { .. } => "status",
                            SyncResponse::Blocks(_) => "blocks",
                            SyncResponse::NodeInfo(_) => "node_info",
                            SyncResponse::Hashes(_) => "hashes",
                            SyncResponse::Certificate { .. } => "certificate",
                        };
                        counter!("arxium_sync_responses_total", "kind" => kind).increment(1);
                        match sync_response {
                            // The node never asks for these — they exist for
                            // followers. Receiving one means a peer answered a
                            // question we didn't ask, so note it and move on
                            // rather than treating it as protocol breakage.
                            SyncResponse::NodeInfo(_) => {
                                warn!("unsolicited {kind} response from {peer}, ignoring");
                            }
                            // Step one of divergence recovery: locate the
                            // first height where this peer's chain and ours
                            // disagree. Only meaningful if we asked.
                            SyncResponse::Hashes(hashes) => {
                                if recovering.remove(&peer) != Some(RecoveryStep::AwaitingHashes) {
                                    warn!("unsolicited hashes response from {peer}, ignoring");
                                    continue;
                                }
                                let divergent = first_divergent_height(&hashes, |height| {
                                    db.get_block::<P>(height).ok().flatten().map(|block| block.hash())
                                });
                                match divergent {
                                    Some(height) => {
                                        info!("divergence with {peer} first appears at height {height}, asking for its certificate there");
                                        recovering.insert(peer, RecoveryStep::AwaitingCertificate(height));
                                        send_sync_request(&mut swarm, &peer, &SyncRequest::Certificate { height });
                                    }
                                    None => warn!(
                                        "peer {peer} serves blocks this node rejects but agrees with it everywhere from the watermark to the tip — not a fork this node can roll back to; giving up on {peer}"
                                    ),
                                }
                            }
                            // Step two: the only input in this whole path that
                            // is allowed to move local state, and only after
                            // this node verifies it against its own validator
                            // set.
                            SyncResponse::Certificate { height, record } => {
                                let Some(RecoveryStep::AwaitingCertificate(expected)) = recovering.remove(&peer) else {
                                    warn!("unsolicited certificate response from {peer}, ignoring");
                                    continue;
                                };
                                if expected != height {
                                    warn!("peer {peer} answered with a certificate for height {height}, not the {expected} we asked about; ignoring");
                                    continue;
                                }
                                let Some(record) = record
                                    .as_deref()
                                    .and_then(|bytes| decode_wire::<FinalityRecord>(bytes).ok())
                                else {
                                    warn!("peer {peer} has no usable certificate at {height}; its claim about this node's chain stays a claim, giving up on it");
                                    continue;
                                };
                                if record.height != height || !verify_finality_record(&db, &record) {
                                    warn!("certificate from {peer} at {height} does not verify against this node's validator set; ignoring it and giving up on {peer}");
                                    continue;
                                }
                                let local_hash = db.get_block::<P>(height).ok().flatten().map(|block| block.hash());
                                if local_hash.as_deref() == Some(record.block_hash.as_str()) {
                                    warn!("certificate from {peer} at {height} certifies the block this node already holds; no rollback warranted");
                                    continue;
                                }
                                let watermark = match db.get_final_watermark() {
                                    Ok(watermark) => watermark,
                                    Err(err) => {
                                        warn!("failed to read final watermark: {err}");
                                        continue;
                                    }
                                };
                                match plan(height, watermark) {
                                    Recovery::HaltBelowWatermark => {
                                        counter!("arxium_divergence_below_watermark_total").increment(1);
                                        // ponytail: latch + loud log, not a
                                        // process-level halt — stopping the
                                        // node needs a shutdown channel into
                                        // `arxd/node` that doesn't exist yet.
                                        // The part that matters now is that
                                        // state is preserved untouched and
                                        // never self-modified after this.
                                        halted_below_watermark = true;
                                        error!(
                                            "HALT: this node's block at height {height} contradicts a finality certificate it verified itself (local {local_hash:?}, certified {}). The network finalized against this node at or below its own watermark {watermark} — this is a fault in this node, not in {peer}. State is preserved untouched for forensics; automatic recovery is now disabled for this process.",
                                            record.block_hash
                                        );
                                    }
                                    Recovery::RevertTo(target) => {
                                        if !allow_revert(&mut last_revert, Instant::now()) {
                                            warn!("revert to {target} suppressed by the cooldown; will retry after it expires");
                                            continue;
                                        }
                                        let tip = local_tip_height(&db);
                                        // Read the actions off before the
                                        // blocks stop existing. Losing them is
                                        // a silent failure — users see dropped
                                        // transactions and nothing logs.
                                        let orphaned: Vec<Action<P>> = (target + 1..=tip)
                                            .filter_map(|h| db.get_block::<P>(h).ok().flatten())
                                            .flat_map(|block| block.actions)
                                            .collect();
                                        match db.revert_to::<P>(target) {
                                            Ok(()) => {
                                                let mut restored = 0usize;
                                                if let Ok(mut mempool) = mempool.lock() {
                                                    for action in orphaned {
                                                        if mempool.push(action).is_ok() {
                                                            restored += 1;
                                                        }
                                                    }
                                                }
                                                counter!("arxium_reverts_total").increment(1);
                                                error!("reverted from height {tip} to {target} in favour of {peer}'s certified chain (divergence at {height}); {restored} action(s) returned to the mempool");
                                                send_sync_request(&mut swarm, &peer, &SyncRequest::Blocks { from: target + 1 });
                                            }
                                            Err(err) => error!("revert to {target} failed and was not applied: {err}"),
                                        }
                                    }
                                }
                            }
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
                                // not new validation logic. Fsync is deferred
                                // per-block (`on_block(_, true)`) and paid
                                // once for the whole page below instead —
                                // this is the batch of up to `MAX_PAGE_SIZE`
                                // already-finalized blocks the response
                                // carries, not a single live block, so there
                                // is nothing to lose by amortizing the fsync
                                // over the page: a crash before `flush_wal`
                                // just means re-fetching this page from a peer.
                                let tip_before = local_tip_height(&db);
                                let page_len = blocks.len();
                                for block in blocks {
                                    if on_block(block, true) {
                                        record_bad_gossip(
                                            &mut swarm,
                                            &mut bad_gossip,
                                            peer,
                                            "sync",
                                            "forged synced block signature",
                                        );
                                    } else {
                                        counter!("arxium_gossip_accepted_total", "topic" => "sync").increment(1);
                                    }
                                }
                                if let Err(err) = db.flush_wal() {
                                    warn!("failed to flush WAL after sync page: {err}");
                                }
                                let local_tip = local_tip_height(&db);
                                info!("synced page of {page_len} block(s) from {peer}: tip {tip_before} -> {local_tip}");
                                let (next_stuck_tip, stuck_rounds) = advance_stuck_tip(stuck_tip, local_tip);
                                stuck_tip = next_stuck_tip;
                                // Past the cap this peer keeps re-serving a
                                // page whose blocks we can never accept — a
                                // genuine divergence, not transient lag —
                                // so stop retrying it instead of looping
                                // request/response forever with zero backoff
                                // (this used to only log once at exactly
                                // `stuck_rounds == MAX_CONSECUTIVE_SYNC_FAILURES`
                                // and then keep spinning, which is what ran a
                                // 40GB disk out of space in production).
                                // Reusing `sync_failures` here means the
                                // periodic `STATUS_INTERVAL` tick already
                                // knows to skip this peer, and a fresh
                                // `ConnectionEstablished` or a success clears
                                // it exactly like any other sync failure.
                                if stuck_rounds >= MAX_CONSECUTIVE_SYNC_FAILURES {
                                    if stuck_rounds == MAX_CONSECUTIVE_SYNC_FAILURES {
                                        // A real divergence, not transient lag.
                                        // Ask the peer to describe its chain
                                        // over the only range a rollback could
                                        // legally target — watermark..=tip.
                                        // Nothing it answers is trusted; the
                                        // hashes only locate the disagreement,
                                        // and a certificate this node verifies
                                        // itself is what decides whether to act
                                        // on it. See `recovery`.
                                        let watermark = db.get_final_watermark().unwrap_or_else(|err| {
                                            warn!("failed to read final watermark: {err}");
                                            local_tip
                                        });
                                        error!(
                                            "local tip stuck at {local_tip} after {stuck_rounds} sync rounds — peer {peer} keeps serving a block this node rejects; attempting divergence recovery over {watermark}..={local_tip}"
                                        );
                                        if halted_below_watermark {
                                            warn!("divergence recovery is latched off after a below-watermark fault; not retrying");
                                        } else {
                                            recovering.insert(peer, RecoveryStep::AwaitingHashes);
                                            send_sync_request(&mut swarm, &peer, &SyncRequest::Hashes {
                                                from: watermark,
                                                to: local_tip,
                                            });
                                        }
                                    }
                                    sync_failures.insert(peer, MAX_CONSECUTIVE_SYNC_FAILURES);
                                } else if peer_tips.get(&peer).is_some_and(|&tip| tip > local_tip) {
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
        let (_dissent_tx, dissent_rx) = tokio_mpsc::unbounded_channel();
        let (_round_timeout_tx, round_timeout_rx) = tokio_mpsc::unbounded_channel();

        let peer_id = spawn_p2p_node(
            &base_path, 0, &[], false, "test-chain", mempool, db, gossip_rx, block_rx, precommit_rx,
            dissent_rx, round_timeout_rx, |_, _| false, |_| {}, |_| {}, |_| {}, None,
        )
        .expect("node should start on OS-assigned port");
        assert!(!peer_id.to_string().is_empty());

        std::fs::remove_dir_all(&base_path).ok();
    }
}
