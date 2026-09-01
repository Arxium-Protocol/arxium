// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::Address;

/// How many validators must precommit to a block before it is final: 2/3 of
/// the set plus one, counted by head rather than weighted by stake.
///
/// Lives here rather than in `arxd/finality` because it is a consensus rule,
/// not a role-specific one, and two callers need it: the subsystem that
/// tallies precommits, and the RPC layer that reports how far the current set
/// is from reaching it. `core/` may not depend on `arxd/`, so a copy in each
/// would be two definitions of one rule, free to drift.
///
/// Not stake-weighted, deliberately: `eligible_proposer` ignores stake too, so
/// weighting finality alone would be incoherent. Both change together or
/// neither does.
pub fn quorum(validator_count: usize) -> usize {
    2 * validator_count / 3 + 1
}

/// How far ahead of the validating node's own wall clock a block's timestamp
/// may be before the block is rejected (`xc_executor::accept_block`).
///
/// This exists because proposer eligibility is derived from block timestamps,
/// so without a bound a proposer picks its own eligibility: stamp a block far
/// enough in the future and `eligible_proposer` returns whatever round that
/// buys, and — worse — every later block's `elapsed` is measured from that
/// poisoned parent, which can stall the rotation for as long as the forged
/// timestamp is ahead. Bounding it caps that to seconds.
///
/// It does **not** fully prevent a proposer from nudging itself a round or
/// two forward; in a small validator set any nonzero allowance can reach any
/// position. Eliminating that needs real BFT voting on time, not a bound.
/// What it does buy is that the damage is bounded and self-correcting rather
/// than permanent.
///
/// 30s is far above the sub-second skew of an NTP-synced host (which every
/// validator should be — see `docs/runbook.md`) and still only a handful of
/// slots. A block rejected for drift is not fatal and not the peer's fault:
/// the node simply stays behind, and sync re-requests the same height a few
/// seconds later, by which point the local clock has caught up.
pub const MAX_FUTURE_DRIFT_SECS: u64 = 30;

/// Deterministic round-robin: sorts the validator set and picks by height
/// modulo its size. No stake weighting — the set can change over time (see
/// `ValidatorChange`), but within a single height every node computes the
/// same primary proposer from the same set.
pub fn expected_proposer(validators: &[Address], height: u64) -> Option<Address> {
    eligible_proposer(validators, height, 0)
}

/// Like `expected_proposer`, but lets a later validator in the rotation
/// stand in once a quorum has certified that an earlier round missed its
/// window.
///
/// `round` is deliberately **not** derived from anything the block itself
/// claims (a timestamp, an elapsed duration) — see `Arxium_OpenItems.md` §7
/// (B1b). It comes from `xc_storage::ArxiumDb::current_round`, which counts
/// persisted `RoundCertificate`s: quorum-BLS-aggregated proof that a quorum
/// of validators independently timed out round `R`, produced by
/// `arxd_finality::tally_round_timeout`. A single validator (or a fast/slow
/// clock) can never move a height to round `R+1` unilaterally — only a
/// quorum's agreement can, and both the proposer and every validating peer
/// read the same persisted certificates, so they always agree on `round`
/// before checking who is eligible for it.
///
/// This replaces the earlier round-0-pinned stopgap (B1a): that fix's known
/// cost — any missed primary slot halted the height forever, since nothing
/// else could ever produce it — is what this closes. A missed primary now
/// recovers once a quorum certifies the timeout, instead of never.
///
/// Any change here must land on every validator binary before any of them
/// uses it — `accept_block` validates historical blocks with the same
/// function that live production consults, so a mixed fleet rejects each
/// other's history, not just new blocks.
pub fn eligible_proposer(validators: &[Address], height: u64, round: u32) -> Option<Address> {
    if validators.is_empty() {
        return None;
    }
    let mut sorted = validators.to_vec();
    sorted.sort();
    let idx = (height as usize).wrapping_add(round as usize) % sorted.len();
    Some(sorted[idx].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    #[test]
    fn empty_validator_set_has_no_proposer() {
        assert_eq!(expected_proposer(&[], 0), None);
    }

    #[test]
    fn cycles_deterministically_regardless_of_input_order() {
        let a = addr(1);
        let b = addr(2);
        let c = addr(3);
        let forward = vec![a.clone(), b.clone(), c.clone()];
        let shuffled = vec![c.clone(), a.clone(), b.clone()];

        for height in 0..9u64 {
            assert_eq!(
                expected_proposer(&forward, height),
                expected_proposer(&shuffled, height),
            );
        }
        // and it actually cycles through all three distinct validators, not just repeating one
        let picks: Vec<_> = (0..3).map(|h| expected_proposer(&forward, h)).collect();
        let mut unique = picks.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3);
        assert_eq!(picks[0], expected_proposer(&forward, 3)); // wraps around
    }

    /// Round 0 always picks the same primary as `expected_proposer` — a
    /// height with no certified timeout has exactly one eligible proposer.
    #[test]
    fn round_zero_is_pinned_to_the_primary() {
        let mut sorted = vec![addr(1), addr(2), addr(3)];
        sorted.sort();
        let a = sorted[0].clone();
        assert_eq!(eligible_proposer(&sorted, 0, 0), Some(a));
    }

    /// A quorum-certified round advance hands eligibility to a *different*
    /// validator — this is what B1b buys over the B1a stopgap: a missed
    /// primary is no longer a permanent halt, because round 1 (and beyond)
    /// has its own eligible proposer once `current_round` says so.
    #[test]
    fn a_higher_round_hands_eligibility_to_a_different_validator() {
        let mut sorted = vec![addr(1), addr(2), addr(3)];
        sorted.sort();
        let round0 = eligible_proposer(&sorted, 0, 0).unwrap();
        let round1 = eligible_proposer(&sorted, 0, 1).unwrap();
        let round2 = eligible_proposer(&sorted, 0, 2).unwrap();
        assert_ne!(round0, round1);
        assert_ne!(round1, round2);
        assert_ne!(round0, round2);
        // and it wraps back around after cycling through every validator
        assert_eq!(eligible_proposer(&sorted, 0, 3), Some(round0));
    }

    /// A single validator is eligible at every round — there is nobody else
    /// to hand a certified timeout to.
    #[test]
    fn a_lone_validator_is_always_eligible() {
        let only = vec![addr(7)];
        for round in [0u32, 1, 4, 9, 1_000, u32::MAX] {
            assert_eq!(eligible_proposer(&only, 5, round), Some(addr(7)));
        }
    }

    /// Input ordering must not change the answer — nodes learn the validator
    /// set from storage and may hold it in any order.
    #[test]
    fn eligibility_is_independent_of_input_ordering() {
        let forward = vec![addr(1), addr(2), addr(3), addr(4)];
        let shuffled = vec![addr(3), addr(1), addr(4), addr(2)];
        for height in 0..8u64 {
            for round in [0u32, 1, 2, 3, 400] {
                assert_eq!(
                    eligible_proposer(&forward, height, round),
                    eligible_proposer(&shuffled, height, round),
                );
            }
        }
    }

    /// `expected_proposer` is `eligible_proposer` at round 0, so the two must
    /// never disagree about who holds a height before any round is certified.
    #[test]
    fn expected_proposer_matches_eligible_at_round_zero() {
        let validators = vec![addr(1), addr(2), addr(3)];
        for height in 0..10u64 {
            assert_eq!(
                expected_proposer(&validators, height),
                eligible_proposer(&validators, height, 0),
            );
        }
    }
}
