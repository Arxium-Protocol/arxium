// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Proof-of-Execution primitives (PoE v5 design, observation-only). Chain-
//! agnostic: no storage, no executor, no wire format. Callers hash what
//! they already have (state roots, actions) and log the result — nothing
//! here is verified or persisted yet.

use serde::Serialize;
use sha2::{Digest, Sha256};
use xc_primitives::Action;

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// `EP = H(pre_state_root ‖ tx_root ‖ post_state_root ‖ resources_used)`,
/// each field length-prefixed so concatenation is unambiguous (same scheme
/// as `xc_storage::ArxiumDb::compute_state_root`).
pub fn execution_proof(
    pre_state_root: &str,
    tx_root: &[u8; 32],
    post_state_root: &str,
    resources_used: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, pre_state_root.as_bytes());
    hash_field(&mut hasher, tx_root);
    hash_field(&mut hasher, post_state_root.as_bytes());
    hash_field(&mut hasher, &resources_used.to_le_bytes());
    hasher.finalize().into()
}

/// Deterministic hash of one action (sender, nonce, payload, signature) —
/// the leaf a block's `tx_root` is built over.
pub fn action_hash<P: Serialize>(action: &Action<P>) -> [u8; 32] {
    let bytes = bincode::serde::encode_to_vec(action, bincode::config::standard())
        .expect("action encoding should never fail");
    Sha256::digest(&bytes).into()
}

/// Binary Merkle root over a block's action hashes; duplicates the last
/// leaf on an odd count at each level. Empty block hashes to `[0u8; 32]`.
pub fn tx_root<P: Serialize>(actions: &[Action<P>]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = actions.iter().map(action_hash).collect();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::Address;

    fn action(nonce: u64) -> Action<u8> {
        Action {
            sender: Address::from_pubkey_bytes(&[nonce as u8; 32]).unwrap(),
            nonce,
            signature: None,
            payload: 0,
        }
    }

    #[test]
    fn execution_proof_changes_when_any_field_changes() {
        let base = execution_proof("0xaa", &[1u8; 32], "0xbb", 10);
        assert_ne!(base, execution_proof("0xcc", &[1u8; 32], "0xbb", 10));
        assert_ne!(base, execution_proof("0xaa", &[2u8; 32], "0xbb", 10));
        assert_ne!(base, execution_proof("0xaa", &[1u8; 32], "0xdd", 10));
        assert_ne!(base, execution_proof("0xaa", &[1u8; 32], "0xbb", 11));
    }

    #[test]
    fn execution_proof_is_deterministic() {
        let a = execution_proof("0xaa", &[1u8; 32], "0xbb", 10);
        let b = execution_proof("0xaa", &[1u8; 32], "0xbb", 10);
        assert_eq!(a, b);
    }

    #[test]
    fn tx_root_empty_block_is_zero() {
        let actions: Vec<Action<u8>> = Vec::new();
        assert_eq!(tx_root(&actions), [0u8; 32]);
    }

    #[test]
    fn tx_root_single_action_is_its_hash() {
        let actions = vec![action(1)];
        assert_eq!(tx_root(&actions), action_hash(&actions[0]));
    }

    #[test]
    fn tx_root_is_order_sensitive() {
        let a = vec![action(1), action(2), action(3)];
        let b = vec![action(1), action(3), action(2)];
        assert_ne!(tx_root(&a), tx_root(&b));
    }

    #[test]
    fn tx_root_odd_count_duplicates_the_last_leaf() {
        let actions = vec![action(1), action(2), action(3)];
        let [h1, h2, h3] = [
            action_hash(&actions[0]),
            action_hash(&actions[1]),
            action_hash(&actions[2]),
        ];
        let left = {
            let mut hasher = Sha256::new();
            hasher.update(h1);
            hasher.update(h2);
            hasher.finalize()
        };
        let right = {
            let mut hasher = Sha256::new();
            hasher.update(h3);
            hasher.update(h3);
            hasher.finalize()
        };
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(tx_root(&actions), expected);
    }
}
