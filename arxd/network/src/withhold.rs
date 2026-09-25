// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Harness-only Byzantine proposer (`--features fault-injection`, never in a
//! normal build; `arxd/node` refuses to boot with it armed off the harness
//! chain). With `ARXD_WITHHOLD_BLOCK_AT_HEIGHT=h`, the block this node
//! produces at `h` is never gossiped, and is served over sync only to the
//! peers in `ARXD_WITHHOLD_EXCEPT_PEERS` — every other peer is told this
//! node's tip is `h − 1` and gets pages cut short before it. Together with
//! `arxd_finality`'s half (never vote at `h`) that is the proposer of
//! `docs/consensus-safety.md` §3; `scripts/withholding-proposer-harness.sh`
//! drives it.
//!
//! Gossip is all-or-nothing (gossipsub publishes to the whole mesh), so the
//! one targeted delivery path is sync: the favoured peer pulls the block on
//! its next `Status` tick, since `blocks_page_end` serves the provisional
//! tip to a peer standing at the watermark.

use anyhow::{Result, anyhow};
use libp2p::PeerId;
use std::collections::HashSet;
use xc_primitives::{Block, Hash32};
use xc_storage::ArxiumDb;

use crate::gossip::Payload;
use crate::sync::SyncResponse;

pub(crate) struct Withhold {
    height: u64,
    deliver_to: HashSet<PeerId>,
    /// Set once this node has actually produced (and swallowed) the block.
    hash: Option<Hash32>,
}

impl Withhold {
    /// `None` unless `ARXD_WITHHOLD_BLOCK_AT_HEIGHT` is set. A malformed
    /// peer id is fatal for the same reason `ARXD_BLOCK_PEERS`' is: a run
    /// that silently delivers to nobody reports a scenario that never ran.
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let Some(height) = arxd_finality::withheld_height() else {
            return Ok(None);
        };
        let deliver_to = std::env::var("ARXD_WITHHOLD_EXCEPT_PEERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(|e| {
                e.parse::<PeerId>().map_err(|err| {
                    anyhow!("ARXD_WITHHOLD_EXCEPT_PEERS: {e:?} is not a peer id: {err}")
                })
            })
            .collect::<Result<_>>()?;
        Ok(Some(Self {
            height,
            deliver_to,
            hash: None,
        }))
    }

    /// `true` if `block` is the one to withhold (so: don't gossip it).
    pub(crate) fn intercept<P: Payload>(&mut self, block: &Block<P>) -> bool {
        if block.height != self.height {
            return false;
        }
        self.hash = Some(block.hash());
        true
    }

    /// Rewrites a sync response so `peer` cannot learn the withheld block
    /// from it. A no-op for favoured peers, and until the block exists.
    pub(crate) fn filter<P: Payload>(
        &self,
        db: &ArxiumDb,
        peer: &PeerId,
        response: SyncResponse<Block<P>>,
    ) -> SyncResponse<Block<P>> {
        let Some(hash) = self.hash else {
            return response;
        };
        if self.deliver_to.contains(peer) {
            return response;
        }
        match response {
            SyncResponse::Status { tip_height }
                if tip_height == self.height
                    && db
                        .get_block::<P>(tip_height)
                        .ok()
                        .flatten()
                        .is_some_and(|b| b.hash() == hash) =>
            {
                SyncResponse::Status {
                    tip_height: tip_height - 1,
                }
            }
            SyncResponse::Blocks(mut blocks) => {
                if let Some(at) = blocks.iter().position(|b| b.hash() == hash) {
                    blocks.truncate(at);
                }
                SyncResponse::Blocks(blocks)
            }
            SyncResponse::Hashes(mut hashes) => {
                if let Some(at) = hashes.iter().position(|(_, h)| *h == hash) {
                    hashes.truncate(at);
                }
                SyncResponse::Hashes(hashes)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::tests::{block, temp_db};

    #[test]
    fn only_the_favoured_peer_can_see_the_withheld_block() {
        let db = temp_db();
        for h in 0..=3 {
            db.write_batch(&block(h)).unwrap();
        }
        let favoured = PeerId::random();
        let other = PeerId::random();
        let mut w = Withhold {
            height: 3,
            deliver_to: HashSet::from([favoured]),
            hash: None,
        };
        assert!(!w.intercept(&block(2)));
        assert!(w.intercept(&block(3)));

        let status = |peer| match w.filter::<()>(&db, &peer, SyncResponse::Status { tip_height: 3 })
        {
            SyncResponse::Status { tip_height } => tip_height,
            _ => unreachable!(),
        };
        assert_eq!(status(other), 2);
        assert_eq!(status(favoured), 3);

        let page = |peer| match w.filter::<()>(
            &db,
            &peer,
            SyncResponse::Blocks((1..=3).map(block).collect()),
        ) {
            SyncResponse::Blocks(blocks) => blocks.len(),
            _ => unreachable!(),
        };
        assert_eq!(page(other), 2);
        assert_eq!(page(favoured), 3);
    }

    #[test]
    fn a_replacement_block_at_the_same_height_is_not_withheld() {
        // Once the round-1 block replaces the withheld one, the tip at that
        // height is no longer the withheld hash and must be reported as is.
        let db = temp_db();
        for h in 0..=2 {
            db.write_batch(&block(h)).unwrap();
        }
        let mut replacement = block(3);
        replacement.round = 1;
        db.write_batch(&replacement).unwrap();
        let mut w = Withhold {
            height: 3,
            deliver_to: HashSet::new(),
            hash: None,
        };
        assert!(w.intercept(&block(3)));
        let SyncResponse::Status { tip_height } = w.filter::<()>(
            &db,
            &PeerId::random(),
            SyncResponse::Status { tip_height: 3 },
        ) else {
            unreachable!()
        };
        assert_eq!(tip_height, 3);
    }
}
