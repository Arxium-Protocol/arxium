// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::Address;

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
    eligible_proposer(validators, height, 0, 1)
}

/// Like `expected_proposer`, but allows a later validator in the rotation to
/// stand in once the primary has missed its window. `elapsed_secs` is the
/// time since the parent block (`block.timestamp - parent.timestamp` when a
/// candidate is validated, or `now - parent.timestamp` when a node is
/// deciding whether it may produce) — never wall-clock-at-receipt, so a live
/// node and one replaying the same block during sync always agree on who was
/// eligible.
///
/// Every full `slot_duration_secs` of silence advances eligibility one
/// validator further along the rotation, **wrapping indefinitely**: after the
/// whole set has been offered a turn, the primary comes back around and the
/// cycle repeats.
///
/// That wrapping is the entire point, and it is a consensus rule — see
/// `Arxium_OpenItems.md` §1. This used to cap the offset at the last
/// validator (`.min(sorted.len() - 1)`), which meant a height whose final
/// fallback was offline could never be produced by anyone, ever: the chain
/// halted at that height while every process stayed healthy. Capping is safe
/// only in the degenerate one-validator case, which is why the devnet ran a
/// single validator as a mitigation. Any change here must land on every
/// validator binary before any of them uses it — `accept_block` validates
/// historical blocks with the same function that live production consults.
pub fn eligible_proposer(
    validators: &[Address],
    height: u64,
    elapsed_secs: u64,
    slot_duration_secs: u64,
) -> Option<Address> {
    if validators.is_empty() {
        return None;
    }
    let mut sorted = validators.to_vec();
    sorted.sort();
    let primary = (height as usize) % sorted.len();
    let round = elapsed_secs / slot_duration_secs.max(1);
    // Reduced as u64 before narrowing: `elapsed_secs` is attacker-influenced
    // (it comes from a proposer's own timestamp), and `as usize` on a 32-bit
    // target would truncate a large round to an arbitrary one instead.
    let offset = (round % sorted.len() as u64) as usize;
    Some(sorted[(primary + offset) % sorted.len()].clone())
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

    #[test]
    fn eligible_proposer_advances_through_rotation_as_primary_goes_silent() {
        let mut sorted = vec![addr(1), addr(2), addr(3)];
        sorted.sort();
        let (a, b, c) = (sorted[0].clone(), sorted[1].clone(), sorted[2].clone());

        // Within the primary's own window, only the primary is eligible.
        assert_eq!(eligible_proposer(&sorted, 0, 0, 4), Some(a.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 3, 4), Some(a.clone()));

        // One full slot of silence hands eligibility to the next validator
        // in rotation order — deterministic from elapsed time alone.
        assert_eq!(eligible_proposer(&sorted, 0, 4, 4), Some(b.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 7, 4), Some(b.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 8, 4), Some(c.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 11, 4), Some(c));
    }

    /// The bug from `Arxium_OpenItems.md` §1, as a test: the rotation
    /// must come back around to the primary rather than parking on the last
    /// validator forever. The previous implementation returned the last
    /// validator for every elapsed time past `slot * (len - 1)`, so a height
    /// whose last fallback was offline could never be produced by anyone.
    #[test]
    fn rotation_wraps_back_to_the_primary_instead_of_parking_on_the_last() {
        let mut sorted = vec![addr(1), addr(2), addr(3)];
        sorted.sort();
        let (a, b, c) = (sorted[0].clone(), sorted[1].clone(), sorted[2].clone());

        // Round 3 is a full cycle later: back to the primary.
        assert_eq!(eligible_proposer(&sorted, 0, 12, 4), Some(a.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 15, 4), Some(a.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 16, 4), Some(b));
        assert_eq!(eligible_proposer(&sorted, 0, 20, 4), Some(c));

        // 1000s = round 250; 250 % 3 == 1, so the primary's successor. The
        // old code returned the last validator here no matter how long it had
        // been. Nothing is ever permanently unproducible now.
        assert_eq!(eligible_proposer(&sorted, 0, 1000, 4), sorted.get(1).cloned());

        // Over many rounds every validator keeps getting offered turns.
        let mut seen: Vec<Address> = (0..30)
            .map(|round| eligible_proposer(&sorted, 0, round * 4, 4).unwrap())
            .collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3, "every validator must keep getting turns");
        assert!(seen.contains(&a));
    }

    /// A single validator is eligible at every elapsed time — there is nobody
    /// to hand a missed slot to. This is what kept the mitigated devnet alive
    /// while the cap was still in place, so it must not regress.
    #[test]
    fn a_lone_validator_is_always_eligible() {
        let only = vec![addr(7)];
        for elapsed in [0u64, 1, 4, 9, 1_000, u64::MAX] {
            assert_eq!(eligible_proposer(&only, 5, elapsed, 4), Some(addr(7)));
        }
    }

    /// Two validators with one offline: the online one has to keep getting
    /// turns. Under the old cap, whichever sorted last held the height
    /// forever once a slot was missed.
    #[test]
    fn an_online_validator_keeps_getting_turns_while_the_other_is_offline() {
        let mut sorted = vec![addr(1), addr(2)];
        sorted.sort();

        // Whichever validator is primary for this height, the *other* one is
        // offline — check both directions rather than assuming an ordering.
        for height in [0u64, 1] {
            let online = eligible_proposer(&sorted, height, 0, 4).unwrap();
            let recovered = (0..12u64)
                .map(|round| eligible_proposer(&sorted, height, round * 4, 4).unwrap())
                .filter(|pick| pick == &online)
                .count();
            assert!(
                recovered >= 5,
                "online validator got only {recovered} turns in 12 rounds at height {height}",
            );
        }
    }

    /// Exact slot boundaries, spelled out — the root-cause doc calls these out
    /// specifically because the stall happened on one (a commit that landed
    /// 2.4s late pushed height 203 across the 4s boundary).
    #[test]
    fn slot_boundaries_select_the_expected_validator() {
        let mut sorted = vec![addr(1), addr(2)];
        sorted.sort();
        let (a, b) = (sorted[0].clone(), sorted[1].clone());

        // Height 0 -> primary is index 0.
        assert_eq!(eligible_proposer(&sorted, 0, 3, 4), Some(a.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 4, 4), Some(b.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 7, 4), Some(b));
        assert_eq!(eligible_proposer(&sorted, 0, 8, 4), Some(a));
    }

    /// Input ordering must not change the answer — nodes learn the validator
    /// set from storage and may hold it in any order.
    #[test]
    fn eligibility_is_independent_of_input_ordering() {
        let forward = vec![addr(1), addr(2), addr(3), addr(4)];
        let shuffled = vec![addr(3), addr(1), addr(4), addr(2)];
        for height in 0..8u64 {
            for elapsed in [0u64, 4, 9, 13, 400] {
                assert_eq!(
                    eligible_proposer(&forward, height, elapsed, 4),
                    eligible_proposer(&shuffled, height, elapsed, 4),
                );
            }
        }
    }

    /// `expected_proposer` is `eligible_proposer` at round 0, so the two must
    /// never disagree about who holds a height before any slot has elapsed.
    #[test]
    fn expected_proposer_matches_eligible_at_round_zero() {
        let validators = vec![addr(1), addr(2), addr(3)];
        for height in 0..10u64 {
            assert_eq!(
                expected_proposer(&validators, height),
                eligible_proposer(&validators, height, 0, 4),
            );
        }
    }

    /// A slot duration of 0 would divide by zero; `max(1)` guards it. Worth a
    /// test because the value reaches here from a caller-supplied config.
    #[test]
    fn zero_slot_duration_does_not_panic() {
        let validators = vec![addr(1), addr(2)];
        assert!(eligible_proposer(&validators, 0, 5, 0).is_some());
    }
}
