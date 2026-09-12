// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Divergence recovery: what a node does when a peer keeps serving blocks it
//! cannot accept.
//!
//! The safety rule this module exists to enforce, stated once:
//!
//! > A node may revert only to a height at or above its contiguous finalized
//! > watermark, and only in favour of a chain carrying finality certificates it
//! > has independently verified.
//!
//! A node that abandons its own chain because a peer disagrees is a node any
//! peer can walk backwards, so nothing here acts on a peer's assertion. The
//! only input that moves local state is a `FinalityRecord` that
//! [`arxd_finality::verify_finality_record`] accepts against *this* node's
//! validator set — everything else ends in giving up on the peer, which is the
//! pre-existing behaviour and is always safe.

use std::time::{Duration, Instant};

/// Minimum gap between two automatic reverts. Without it a peer that can
/// trigger a revert can trigger them back to back and stall this node
/// indefinitely without ever being wrong about anything: each revert throws
/// away work, sync re-fetches, and the cycle repeats at network round-trip
/// speed. One revert per cooldown is still fast enough to recover from a real
/// partition heal within a block or two of sync.
pub(crate) const REVERT_COOLDOWN: Duration = Duration::from_secs(60);

/// Where a peer's chain first stops matching this node's, given the peer's
/// `(height, hash)` page in ascending order and a lookup for the local hash at
/// a height.
///
/// `None` means every height the peer reported matches locally — the
/// disagreement, whatever it is, is not a fork of the range we compared, so
/// there is nothing to roll back to. A height the peer reported that this node
/// doesn't have is not a disagreement either: it's just the peer being ahead.
pub(crate) fn first_divergent_height(
    remote: &[(u64, String)],
    local_hash: impl Fn(u64) -> Option<String>,
) -> Option<u64> {
    remote
        .iter()
        .find(|(height, hash)| local_hash(*height).is_some_and(|local| &local != hash))
        .map(|(height, _)| *height)
}

/// Which reply this node is waiting for from a peer it opened a recovery
/// conversation with. Absent means it opened none, and an unsolicited reply is
/// dropped: a peer must never be able to start a rollback this node didn't ask
/// for.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum RecoveryStep {
    AwaitingHashes,
    AwaitingCertificate(u64),
    /// Not a divergence at all: this node holds blocks it has no certificate
    /// for, and is walking its watermark up to its tip one height at a time.
    /// Sync carries blocks but not certificates, and the precommit votes a
    /// certificate is built from are deleted once the height finalizes and are
    /// never re-gossiped — so a node that caught up by syncing has no way to
    /// certify what it just downloaded, and its watermark would otherwise sit
    /// below the gap forever. Same request, same verification, same persist
    /// path as a divergence; only the reason for asking differs.
    BackfillingCertificate(u64),
}

impl RecoveryStep {
    /// The height a `Certificate` response from this step must answer for.
    pub(crate) fn awaited_certificate_height(self) -> Option<u64> {
        match self {
            RecoveryStep::AwaitingCertificate(height)
            | RecoveryStep::BackfillingCertificate(height) => Some(height),
            RecoveryStep::AwaitingHashes => None,
        }
    }
}

/// What to do about a divergence at `divergent`, given this node's watermark.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Unwind to this height and resume syncing. Always `>= watermark`.
    RevertTo(u64),
    /// The divergence is at or below the watermark: this node committed to
    /// something the network certified against. That is a fault in *this*
    /// node, not a reason to reshape itself to match whoever spoke last.
    HaltBelowWatermark,
}

pub(crate) fn plan(divergent: u64, watermark: u64) -> Recovery {
    // Reverting *to* `divergent - 1` keeps `divergent - 1 >= watermark`, so the
    // watermark height itself is never unwound. A divergence at the watermark
    // means the certified block at that height is not the one we hold.
    match divergent.checked_sub(1) {
        Some(target) if target >= watermark => Recovery::RevertTo(target),
        _ => Recovery::HaltBelowWatermark,
    }
}

/// Whether a revert is allowed now, updating the cooldown if so. See
/// [`REVERT_COOLDOWN`].
pub(crate) fn allow_revert(last: &mut Option<Instant>, now: Instant) -> bool {
    if last.is_some_and(|last| now.duration_since(last) < REVERT_COOLDOWN) {
        return false;
    }
    *last = Some(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(entries: &[(u64, &str)]) -> Vec<(u64, String)> {
        entries.iter().map(|(h, s)| (*h, s.to_string())).collect()
    }

    #[test]
    fn agreement_everywhere_is_not_a_divergence() {
        let remote = page(&[(10, "a"), (11, "b"), (12, "c")]);
        assert_eq!(
            first_divergent_height(&remote, |h| Some(["a", "b", "c"][h as usize - 10].into())),
            None
        );
    }

    #[test]
    fn finds_the_first_mismatch_not_the_last() {
        let remote = page(&[(10, "a"), (11, "X"), (12, "Y")]);
        let local = |h: u64| Some(["a", "b", "c"][h as usize - 10].to_string());
        assert_eq!(first_divergent_height(&remote, local), Some(11));
    }

    #[test]
    fn heights_we_dont_have_are_the_peer_being_ahead_not_a_fork() {
        let remote = page(&[(10, "a"), (11, "b")]);
        assert_eq!(
            first_divergent_height(&remote, |h| (h == 10).then(|| "a".to_string())),
            None
        );
    }

    #[test]
    fn revert_target_is_one_below_the_divergence() {
        assert_eq!(plan(11, 5), Recovery::RevertTo(10));
    }

    #[test]
    fn a_divergence_at_the_watermark_halts_rather_than_reverting_through_it() {
        assert_eq!(plan(5, 5), Recovery::HaltBelowWatermark);
        assert_eq!(plan(4, 5), Recovery::HaltBelowWatermark);
        assert_eq!(plan(0, 0), Recovery::HaltBelowWatermark);
    }

    #[test]
    fn the_cooldown_lets_the_first_revert_through_and_rate_limits_the_next() {
        let mut last = None;
        let start = Instant::now();
        assert!(allow_revert(&mut last, start));
        assert!(!allow_revert(&mut last, start + REVERT_COOLDOWN / 2));
        assert!(allow_revert(&mut last, start + REVERT_COOLDOWN));
    }
}
