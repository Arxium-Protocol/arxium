use crate::Address;

/// Deterministic round-robin: sorts the validator set and picks by height
/// modulo its size. No stake weighting — the set can change over time (see
/// `ValidatorChange`), but within a single height every node computes the
/// same primary proposer from the same set.
pub fn expected_proposer(validators: &[Address], height: u64) -> Option<Address> {
    eligible_proposer(validators, height, 0, 1)
}

/// Like `expected_proposer`, but allows a later validator in the rotation to
/// stand in once the primary has missed its window. `elapsed_secs` is the
/// time since the parent block (`block.timestamp - parent.timestamp` for a
/// candidate being validated, or `now - parent.timestamp` for a node
/// deciding whether it may produce) — never wall-clock-at-receipt, so a live
/// node and one replaying the same block during sync always agree on who was
/// eligible. Every full `slot_duration_secs` of silence advances eligibility
/// one validator further in rotation order, wrapping at most once around the
/// set (a validator never gets two independent slots at the same height).
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
    let skip = ((elapsed_secs / slot_duration_secs.max(1)) as usize).min(sorted.len() - 1);
    Some(sorted[(primary + skip) % sorted.len()].clone())
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
        assert_eq!(eligible_proposer(&sorted, 0, 3, 4), Some(a));

        // One full slot of silence hands eligibility to the next validator
        // in rotation order — deterministic from elapsed time alone.
        assert_eq!(eligible_proposer(&sorted, 0, 4, 4), Some(b.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 7, 4), Some(b));

        // Never skips past the whole set — caps at the last validator
        // rather than wrapping back onto the primary.
        assert_eq!(eligible_proposer(&sorted, 0, 8, 4), Some(c.clone()));
        assert_eq!(eligible_proposer(&sorted, 0, 1000, 4), Some(c));
    }
}
