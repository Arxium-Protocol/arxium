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
///
/// `resources_used` has no real metering yet (`PoE_v5_design.md` names it in
/// the formula but never defines a unit) — pass `0` until gas/compute
/// accounting exists rather than a stand-in that could be misread as real.
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

#[derive(Debug, thiserror::Error)]
#[error("action failed to encode for hashing")]
pub struct ActionEncodeError(#[from] bincode::error::EncodeError);

// RFC 6962 domain separation (as in Certificate Transparency): leaves and
// internal nodes are hashed under different prefixes so an internal node's
// hash can never be replayed as a leaf (CVE-2012-2459-style second
// preimage).
const LEAF_PREFIX: [u8; 1] = [0x00];
const NODE_PREFIX: [u8; 1] = [0x01];

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(data);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Deterministic hash of one action (sender, nonce, payload, signature) —
/// the leaf a block's `tx_root` is built over. `P` is an arbitrary spoke
/// chain's payload type, so encoding is fallible — this must not panic the
/// producer over a bad `Serialize` impl it doesn't control.
pub fn action_hash<P: Serialize>(action: &Action<P>) -> Result<[u8; 32], ActionEncodeError> {
    let bytes = bincode::serde::encode_to_vec(action, bincode::config::standard())?;
    Ok(leaf_hash(&bytes))
}

/// Binary Merkle root over a block's action hashes (RFC 6962 shape, as used
/// by Certificate Transparency): leaves and internal nodes are hashed under
/// distinct domain prefixes, and an odd node at any level is promoted
/// unchanged to the next level rather than duplicated — duplication is the
/// CVE-2012-2459 bug (Bitcoin's `[a,b,c]` and `[a,b,c,c]` hashing equal).
/// Empty block hashes to `[0u8; 32]`.
pub fn tx_root<P: Serialize>(actions: &[Action<P>]) -> Result<[u8; 32], ActionEncodeError> {
    let mut level: Vec<[u8; 32]> = actions.iter().map(action_hash).collect::<Result<_, _>>()?;
    if level.is_empty() {
        return Ok([0u8; 32]);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut pairs = level.chunks_exact(2);
        for pair in &mut pairs {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        if let [odd] = pairs.remainder() {
            next.push(*odd);
        }
        level = next;
    }
    Ok(level[0])
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
        assert_eq!(tx_root(&actions).unwrap(), [0u8; 32]);
    }

    #[test]
    fn tx_root_single_action_is_its_hash() {
        let actions = vec![action(1)];
        assert_eq!(tx_root(&actions).unwrap(), action_hash(&actions[0]).unwrap());
    }

    #[test]
    fn tx_root_is_order_sensitive() {
        let a = vec![action(1), action(2), action(3)];
        let b = vec![action(1), action(3), action(2)];
        assert_ne!(tx_root(&a).unwrap(), tx_root(&b).unwrap());
    }

    /// Regression guard for CVE-2012-2459: odd-leaf duplication must not
    /// make a 3-action block and a 4-action block (last action repeated)
    /// hash equal.
    #[test]
    fn tx_root_does_not_collide_when_the_odd_leaf_is_duplicated_upstream() {
        let three = vec![action(1), action(2), action(3)];
        let mut four = three.clone();
        four.push(action(3));
        assert_ne!(tx_root(&three).unwrap(), tx_root(&four).unwrap());
    }

    /// Regression guard for leaf/node confusion: an internal node's hash
    /// must never equal a leaf hash, so a 2-action tree's root can't be
    /// replayed as a single action's leaf.
    #[test]
    fn tx_root_of_pair_differs_from_a_leaf_hash_of_their_combined_root() {
        let pair = vec![action(1), action(2)];
        let root = tx_root(&pair).unwrap();
        let single = vec![action(99)];
        assert_ne!(root, action_hash(&single[0]).unwrap());
        // The old (buggy) scheme hashed nodes identically to leaves, i.e.
        // node_hash(h1, h2) == Sha256(h1 ++ h2) with no domain prefix. Make
        // sure that specific collision doesn't reappear either.
        let h1 = action_hash(&pair[0]).unwrap();
        let h2 = action_hash(&pair[1]).unwrap();
        let mut undomained = Sha256::new();
        undomained.update(h1);
        undomained.update(h2);
        let undomained: [u8; 32] = undomained.finalize().into();
        assert_ne!(root, undomained);
    }

    #[test]
    fn tx_root_odd_count_promotes_the_last_leaf_unchanged() {
        let actions = vec![action(1), action(2), action(3)];
        let h1 = action_hash(&actions[0]).unwrap();
        let h2 = action_hash(&actions[1]).unwrap();
        let h3 = action_hash(&actions[2]).unwrap();
        let expected = node_hash(&node_hash(&h1, &h2), &h3);
        assert_eq!(tx_root(&actions).unwrap(), expected);
    }
}
