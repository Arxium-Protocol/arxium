// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

pub mod identity;
mod discovery;
mod gossip;
mod sync;
mod transport;

pub use gossip::Payload;
pub use libp2p::PeerId;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, gossipsub, mdns};
use metrics::counter;
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info, warn};

use finality::PrecommitVote;
use xc_mempool::{Mempool, PayloadPrecheck, validate_action};
use xc_primitives::{Action, Block};
use xc_storage::ArxiumDb;

use discovery::{dial_bootnodes, dial_discovered};
use gossip::{actions_topic, blocks_topic, precommits_topic, record_bad_gossip};
use sync::{
    MAX_CONSECUTIVE_SYNC_FAILURES, NodeInfo, STATUS_INTERVAL, SyncRequest, SyncResponse,
    advance_stuck_tip, local_tip_height,
    send_sync_request,
};
use transport::{BehaviourEvent, build_swarm};

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
    // Returns `true` if the block's signature is itself forged, so the
    // sending peer can be penalized — see `record_bad_gossip`. Second
    // argument is `sync`: true when applying a `SyncRequest::Blocks` page
    // during catch-up (fsync deferred to one `flush_wal` per page below),
    // false for a single gossiped block (fsync immediately).
    on_block: impl Fn(Block<P>, bool) -> bool + Send + 'static,
    // Undecodable-bytes handling only — `arxd/finality` owns signature and
    // quorum validation, this crate just moves bytes.
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
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
            on_block, on_precommit_vote, payload_precheck, ready_tx,
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
    on_block: impl Fn(Block<P>, bool) -> bool + Send + 'static,
    on_precommit_vote: impl Fn(PrecommitVote) + Send + 'static,
    payload_precheck: Option<PayloadPrecheck<P>>,
    ready_tx: std_mpsc::Sender<Result<()>>,
) {
    let mut swarm = match build_swarm(keypair) {
        Ok(swarm) => swarm,
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            return;
        }
    };

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
    // (state genuinely diverged from this peer — there's no reorg/rollback
    // in this codebase to recover automatically) logs once loudly instead
    // of an unbounded `warn!` every `STATUS_INTERVAL` forever.
    let mut stuck_tip: Option<(u64, u32)> = None;

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
                match bincode::serde::encode_to_vec(&block, bincode::config::standard()) {
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
                match bincode::serde::encode_to_vec(&vote, bincode::config::standard()) {
                    Ok(bytes) => {
                        if let Err(err) = swarm.behaviour_mut().gossipsub.publish(precommits_topic.clone(), bytes) {
                            log_publish_error("precommit vote", &err);
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
                                "precommits",
                                &format!("undecodable gossiped precommit vote: {err}"),
                            );
                            continue;
                        }
                    };
                    counter!("arxium_gossip_accepted_total", "topic" => "precommits").increment(1);
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
                        let sync_response: SyncResponse<Block<P>> = match bincode::serde::decode_from_slice(
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
                        let kind = match &sync_response {
                            SyncResponse::Status { .. } => "status",
                            SyncResponse::Blocks(_) => "blocks",
                            SyncResponse::NodeInfo(_) => "node_info",
                            SyncResponse::Hashes(_) => "hashes",
                        };
                        counter!("arxium_sync_responses_total", "kind" => kind).increment(1);
                        match sync_response {
                            // The node never asks for these — they exist for
                            // followers. Receiving one means a peer answered a
                            // question we didn't ask, so note it and move on
                            // rather than treating it as protocol breakage.
                            SyncResponse::NodeInfo(_) | SyncResponse::Hashes(_) => {
                                warn!("unsolicited {kind} response from {peer}, ignoring");
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
                                        error!(
                                            "local tip stuck at {local_tip} after {stuck_rounds} sync rounds — peer {peer} keeps serving a block this node rejects (state has diverged; no automatic reorg/rollback exists, needs manual intervention); giving up on {peer} until it reconnects or another peer reports progress"
                                        );
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

        let peer_id = spawn_p2p_node(
            &base_path, 0, &[], false, "test-chain", mempool, db, gossip_rx, block_rx, precommit_rx,
            |_, _| false, |_| {}, None,
        )
        .expect("node should start on OS-assigned port");
        assert!(!peer_id.to_string().is_empty());

        std::fs::remove_dir_all(&base_path).ok();
    }
}
