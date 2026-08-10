use crate::Address;

/// Deterministic round-robin: sorts the validator set and picks by height
/// modulo its size. No stake weighting, no dynamic membership — validators
/// come from the static genesis set for now.
pub fn expected_proposer(validators: &[Address], height: u64) -> Option<Address> {
    if validators.is_empty() {
        return None;
    }
    let mut sorted = validators.to_vec();
    sorted.sort();
    Some(sorted[(height as usize) % sorted.len()].clone())
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
}
