// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use libp2p::PeerId;
use metrics::counter;
use std::time::Duration;
use tracing::warn;
use xc_primitives::Block;
use xc_storage::ArxiumDb;

use crate::gossip::Payload;
use crate::transport::Behaviour;

/// Request/response protocol a node uses to catch up on blocks it missed
/// (e.g. was offline for) instead of only ever hearing about the newest
/// block over gossip. Same acceptance path as gossiped blocks — this only
/// adds a second delivery mechanism, not new validation.
///
/// The shapes themselves live in `xc-wire` so external consumers compile
/// against the same definitions instead of copying them; see that crate for the
/// variant-compatibility rules.
pub(crate) use xc_wire::sync_protocol;
/// How often a connected peer is re-asked for its tip, to catch a peer
/// falling behind mid-connection (not just "was offline, just reconnected") —
/// e.g. a gossiped block silently dropped rather than erroring, which the
/// OutboundFailure retry above can't see. Kept a small multiple of a
/// devnet-scale block interval (~2s) rather than a long fixed value, so a
/// missed block self-heals in a couple of block times, not tens of seconds.
pub(crate) const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// A peer whose sync requests fail this many times in a row (without a
/// success in between) stops being retried until it reconnects — a flapping
/// connection otherwise retries every single failure immediately, which on a
/// bad link produces dozens of retries per second forever. Past this cap the
/// peer is just skipped by the `STATUS_INTERVAL` tick; `ConnectionEstablished`
/// (a real reconnect) or any successful sync response clears the count.
pub(crate) const MAX_CONSECUTIVE_SYNC_FAILURES: u32 = 5;

pub(crate) use xc_wire::{NodeInfo, SyncRequest, SyncResponse};

pub(crate) fn local_tip_height(db: &ArxiumDb) -> u64 {
    db.get_tip_height().ok().flatten().unwrap_or(0)
}

/// Answers one inbound `SyncRequest` by reading `db` — the part of the sync
/// protocol's request handling that doesn't touch the swarm or a response
/// channel, pulled out so it's a plain function a test can drive directly
/// instead of only being reachable by decoding wire bytes inside the event
/// loop. `peer` is for the warn! messages only; every branch here degrades
/// to an empty/`None` result on a storage error rather than panicking, since
/// a malformed or out-of-range request from a peer must never take the node
/// down.
pub(crate) fn build_sync_response<P: Payload>(db: &ArxiumDb, peer: PeerId, request: SyncRequest) -> SyncResponse<Block<P>> {
    match request {
        SyncRequest::Status => SyncResponse::<Block<P>>::Status { tip_height: local_tip_height(db) },
        SyncRequest::Blocks { from } => {
            // Bodies are served only up to what a quorum has certified. A
            // block past that is still provisional here — `arxd_finality`
            // unwinds it if the certificate names another — and shipping it
            // makes a catching-up peer commit to the same guess, so a local
            // reorg becomes one every follower has to repeat. The
            // unfinalized tip reaches peers over gossip instead, where a
            // node that acted on it is already tracking the votes that
            // settle it.
            //
            // ponytail: a chain with no certificate at all falls back to the
            // tip, so a fresh or single-node devnet still syncs before its
            // first height finalizes. Once anything has finalized, the clamp
            // is unconditional — a chain that has stopped finalizing stops
            // handing out history to build on, which is the intent.
            let tip_height = local_tip_height(db);
            //
            // The watermark, not the highest certificate: it is contiguous
            // and already cross-checked against the block this node actually
            // holds (see `stage_watermark_advance`), so it is the one value
            // that means "committed here" rather than "certified somewhere".
            let watermark = db.get_final_watermark().unwrap_or_else(|err| {
                warn!("failed to read finalized watermark for sync response to {peer}: {err}");
                0
            });
            let to = if watermark == 0 { tip_height } else { watermark };
            let blocks = db.get_block_range::<P>(from, to).unwrap_or_else(|err| {
                warn!("failed to read blocks {from}..={to} for sync response to {peer}: {err}");
                Vec::new()
            });
            SyncResponse::Blocks(blocks)
        }
        // Everything a follower would otherwise have to hardcode or guess:
        // the page size it must match, how far finality has actually got,
        // and which wire generation we speak.
        SyncRequest::NodeInfo => {
            let tip_height = local_tip_height(db);
            let tip_hash = db
                .get_block_range::<P>(tip_height, tip_height)
                .ok()
                .and_then(|blocks| blocks.first().map(|b| b.hash()));
            SyncResponse::<Block<P>>::NodeInfo(NodeInfo {
                wire_version: xc_wire::WIRE_VERSION,
                tip_height,
                tip_hash,
                finalized_height: db.get_finalized_height().unwrap_or_else(|err| {
                    warn!("failed to read finalized height: {err}");
                    None
                }),
                max_page_size: xc_storage::MAX_PAGE_SIZE as u32,
            })
        }
        // Hashes without bodies, so a follower resolving a fork can
        // binary-search for the common ancestor instead of downloading one
        // block per round trip.
        SyncRequest::Hashes { from, to } => {
            let to = to.min(local_tip_height(db));
            let hashes = db
                .get_block_range::<P>(from, to)
                .unwrap_or_else(|err| {
                    warn!("failed to read blocks {from}..={to} for hash response to {peer}: {err}");
                    Vec::new()
                })
                .into_iter()
                .map(|block| (block.height, block.hash()))
                .collect();
            SyncResponse::<Block<P>>::Hashes(hashes)
        }
        // Serving this is what lets a diverged peer check our claim instead
        // of taking it on faith — see `recovery`.
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
    }
}

/// Advances the "is the tip stuck" tracker after processing one sync page,
/// and decides whether to keep retrying this peer.
///
/// Pulled out of the sync event loop so the one behavior that actually
/// matters here — a peer that keeps re-serving a page this node can never
/// accept eventually gets cut off instead of retried forever — is a plain
/// function a test can drive without spinning up a swarm. Before this
/// existed, the loop only *logged* once at the cap and then kept
/// request/responding with zero backoff, which is what ran a 40GB disk out
/// of space in production: an unbounded WARN-per-rejected-block loop bounded
/// only by network round-trip time.
///
/// Returns the updated tracker and the number of consecutive rounds the tip
/// has been stuck at its current height (0 if this round made progress).
pub(crate) fn advance_stuck_tip(stuck_tip: Option<(u64, u32)>, local_tip: u64) -> (Option<(u64, u32)>, u32) {
    match stuck_tip {
        Some((height, rounds)) if height == local_tip => {
            let rounds = rounds + 1;
            (Some((height, rounds)), rounds)
        }
        _ => (Some((local_tip, 0)), 0),
    }
}

pub(crate) fn send_sync_request(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: &PeerId,
    request: &SyncRequest,
) {
    let kind = match request {
        SyncRequest::Status => "status",
        SyncRequest::Blocks { .. } => "blocks",
        SyncRequest::NodeInfo => "node_info",
        SyncRequest::Hashes { .. } => "hashes",
        SyncRequest::Certificate { .. } => "certificate",
    };
    match bincode::serde::encode_to_vec(request, bincode::config::standard()) {
        Ok(bytes) => {
            counter!("arxium_sync_requests_total", "kind" => kind).increment(1);
            swarm.behaviour_mut().sync.send_request(peer, bytes);
        }
        Err(err) => warn!("failed to encode sync request: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_resets_the_stuck_counter() {
        let (state, rounds) = advance_stuck_tip(Some((10, 3)), 11);
        assert_eq!(state, Some((11, 0)));
        assert_eq!(rounds, 0);
    }

    #[test]
    fn no_progress_increments_the_stuck_counter() {
        let (state, rounds) = advance_stuck_tip(Some((10, 3)), 10);
        assert_eq!(state, Some((10, 4)));
        assert_eq!(rounds, 4);
    }

    #[test]
    fn stuck_counter_keeps_climbing_past_the_cap() {
        // Regression check for the production incident: rounds must keep
        // being reported past `MAX_CONSECUTIVE_SYNC_FAILURES` so the caller
        // can cut the peer off on every round past the cap, not just the
        // one round where it was first hit.
        let mut state = Some((10, MAX_CONSECUTIVE_SYNC_FAILURES - 1));
        for expected in MAX_CONSECUTIVE_SYNC_FAILURES..MAX_CONSECUTIVE_SYNC_FAILURES + 3 {
            let (next_state, rounds) = advance_stuck_tip(state, 10);
            assert_eq!(rounds, expected);
            state = next_state;
        }
    }

    #[test]
    fn first_observation_starts_at_zero_rounds() {
        let (state, rounds) = advance_stuck_tip(None, 5);
        assert_eq!(state, Some((5, 0)));
        assert_eq!(rounds, 0);
    }

    fn temp_db() -> ArxiumDb {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "arxium-test-sync-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        ArxiumDb::open(&path).unwrap()
    }

    fn block(height: u64) -> Block<()> {
        Block {
            height,
            parent_hash: "0xparent".into(),
            timestamp: height,
            actions: vec![],
            tx_root: [0u8; 32],
            proposer: None,
            signature: None,
            state_root: String::new(),
            round: 0,
            round_certificate: None,
        }
    }

    // Adversarial coverage for `build_sync_response`, extracted from the
    // sync event loop precisely so a peer sending an out-of-range,
    // already-rejected, or otherwise malformed request can be exercised
    // directly instead of only through a live swarm.

    fn certify(db: &ArxiumDb, height: u64) {
        let block_hash = db.get_block::<()>(height).unwrap().expect("block to certify").hash();
        db.write_batch(&xc_storage::FinalityRecord {
            height,
            block_hash,
            signers: vec![],
            aggregate_signature: xc_bls::BlsSignature([0u8; 96]),
            ep: [0u8; 32],
        })
        .unwrap();
    }

    #[test]
    fn block_bodies_stop_at_the_finalized_watermark() {
        let db = temp_db();
        for h in 0..=5 {
            db.write_batch(&block(h)).unwrap();
        }
        for h in 1..=3 {
            certify(&db, h);
        }
        assert_eq!(db.get_final_watermark().unwrap(), 3);

        let SyncResponse::Blocks(blocks) =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Blocks { from: 0 })
        else {
            panic!("expected Blocks response");
        };
        // 4 and 5 are held locally and reported by `Status`, but they are
        // still provisional — a peer must not build on them.
        assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), vec![0, 1, 2, 3]);

        // Hashes are deliberately not clamped: a diverged peer resolving a
        // fork has to be able to compare the unfinalized tip too.
        let SyncResponse::Hashes(hashes) =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Hashes { from: 0, to: 99 })
        else {
            panic!("expected Hashes response");
        };
        assert_eq!(hashes.len(), 6);
    }

    #[test]
    fn a_chain_that_has_finalized_nothing_still_serves_its_tip() {
        let db = temp_db();
        for h in 0..=2 {
            db.write_batch(&block(h)).unwrap();
        }
        let SyncResponse::Blocks(blocks) =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Blocks { from: 0 })
        else {
            panic!("expected Blocks response");
        };
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn blocks_request_from_past_the_tip_is_an_empty_page_not_an_error() {
        let db = temp_db();
        db.write_batch(&block(0)).unwrap();
        db.write_batch(&block(1)).unwrap();
        let SyncResponse::Blocks(blocks) = build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Blocks { from: 50 })
        else {
            panic!("expected Blocks response");
        };
        assert!(blocks.is_empty());
    }

    #[test]
    fn blocks_request_from_genesis_returns_the_whole_chain() {
        let db = temp_db();
        for h in 0..=3 {
            db.write_batch(&block(h)).unwrap();
        }
        let SyncResponse::Blocks(blocks) = build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Blocks { from: 0 })
        else {
            panic!("expected Blocks response");
        };
        assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn hashes_request_past_the_tip_is_clamped_not_rejected() {
        let db = temp_db();
        db.write_batch(&block(0)).unwrap();
        db.write_batch(&block(1)).unwrap();
        let SyncResponse::Hashes(hashes) =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Hashes { from: 0, to: 999 })
        else {
            panic!("expected Hashes response");
        };
        // Clamped to the real tip (1), not the peer's claimed upper bound.
        assert_eq!(hashes.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn certificate_request_for_an_unfinalized_height_returns_none_not_a_panic() {
        let db = temp_db();
        db.write_batch(&block(0)).unwrap();
        let SyncResponse::Certificate { height, record } =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Certificate { height: 0 })
        else {
            panic!("expected Certificate response");
        };
        assert_eq!(height, 0);
        assert_eq!(record, None);
    }

    #[test]
    fn certificate_request_for_a_height_never_reached_returns_none_not_a_panic() {
        let db = temp_db();
        let SyncResponse::Certificate { record, .. } =
            build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Certificate { height: 12345 })
        else {
            panic!("expected Certificate response");
        };
        assert_eq!(record, None);
    }

    #[test]
    fn node_info_on_an_empty_chain_reports_tip_zero_with_no_hash() {
        let db = temp_db();
        let SyncResponse::NodeInfo(info) = build_sync_response::<()>(&db, PeerId::random(), SyncRequest::NodeInfo) else {
            panic!("expected NodeInfo response");
        };
        assert_eq!(info.tip_height, 0);
        // No block has ever been written, so genesis itself can't be
        // resolved to a hash — must degrade to `None`, not panic or fabricate one.
        assert_eq!(info.tip_hash, None);
    }

    #[test]
    fn status_request_reports_the_real_local_tip() {
        let db = temp_db();
        db.write_batch(&block(0)).unwrap();
        db.write_batch(&block(1)).unwrap();
        db.write_batch(&block(2)).unwrap();
        let SyncResponse::Status { tip_height } = build_sync_response::<()>(&db, PeerId::random(), SyncRequest::Status)
        else {
            panic!("expected Status response");
        };
        assert_eq!(tip_height, 2);
    }
}
