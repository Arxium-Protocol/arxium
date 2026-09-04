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

/// EP for a block, given its parent's post-state root. The single place
/// this is derived: producer (`arxd/node/src/produce.rs`) and attester
/// (`arxd/finality`) must not compute it two ways.
///
/// `resources_used` is hardcoded 0 until real metering exists — see
/// `execution_proof`'s doc comment.
pub fn block_ep(parent_state_root: &str, block_tx_root: &[u8; 32], block_state_root: &str) -> [u8; 32] {
    execution_proof(parent_state_root, block_tx_root, block_state_root, 0)
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

/// The sparse Merkle trie behind `xc_storage::ArxiumDb::compute_state_root`
/// (`B3`) — hash functions, default-subtree table, and inclusion/
/// non-inclusion proof verification, kept here (not in `core/storage`) so a
/// party with no node — `arx-verify`, a light wallet — can check a proof
/// without pulling in RocksDB. `core/storage` builds proofs by walking its
/// persisted `CF_MERKLE` nodes; this module only ever recomputes a root from
/// a proof already in hand, so it needs no storage backend of its own.
pub mod state_trie {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    pub fn hash_key(key: &[u8]) -> [u8; 32] {
        Sha256::digest(key).into()
    }

    /// Domain-separated from `internal_hash` (leading `0x00` vs `0x01`) so a
    /// leaf and an internal node can never collide in the trie's shared
    /// hash-keyed namespace.
    pub fn leaf_hash(key_hash: &[u8; 32], value: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(key_hash);
        hasher.update(value);
        hasher.finalize().into()
    }

    pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Bit `level` (0 = most significant) of a 256-bit path — which child to
    /// descend into at that level of the trie.
    pub fn bit_at(hash: &[u8; 32], level: usize) -> u8 {
        (hash[level / 8] >> (7 - level % 8)) & 1
    }

    /// `defaults[d]` is the root hash of a subtree of depth `d` containing no
    /// occupied leaves — `defaults[0]` is the canonical "empty leaf" sentinel,
    /// `defaults[d] = internal_hash(defaults[d-1], defaults[d-1])` for `d` up
    /// to 256 (an empty whole trie). Precomputed once per process.
    pub fn default_hashes() -> &'static [[u8; 32]; 257] {
        static DEFAULTS: OnceLock<[[u8; 32]; 257]> = OnceLock::new();
        DEFAULTS.get_or_init(|| {
            let mut table = [[0u8; 32]; 257];
            for depth in 1..=256 {
                table[depth] = internal_hash(&table[depth - 1], &table[depth - 1]);
            }
            table
        })
    }

    /// A key's membership (`value: Some`) or non-membership (`value: None`)
    /// under a given root: the leaf's value plus the sibling at each of the
    /// 256 levels from the root down to the leaf, in that order. Bisection
    /// (Part 3 Stage 3) proves individual state-key reads/writes this way
    /// without either party needing the full trie.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InclusionProof {
        pub key_hash: [u8; 32],
        pub value: Option<Vec<u8>>,
        pub siblings: Vec<[u8; 32]>,
    }

    /// Recomputes the root `proof` implies and checks it equals `root`. A
    /// sparse Merkle tree proves absence the same way it proves presence: a
    /// `None` value just means the path is expected to bottom out at the
    /// canonical empty-leaf hash instead of a real leaf.
    pub fn verify_proof(root: [u8; 32], proof: &InclusionProof) -> bool {
        if proof.siblings.len() != 256 {
            return false;
        }
        let defaults = default_hashes();
        let mut current = match &proof.value {
            Some(value) => leaf_hash(&proof.key_hash, value),
            None => defaults[0],
        };
        for level in (0..256).rev() {
            let sibling = proof.siblings[level];
            let (left, right) =
                if bit_at(&proof.key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
            current = internal_hash(&left, &right);
        }
        current == root
    }

    /// A key not covered by any proof this trie was built or updated from —
    /// distinct from `Ok(None)` (proven absent). The whole point of a
    /// proof-backed trie is to fail closed exactly here: silently treating
    /// an unproven key as absent would let a party who "forgot" a proof (or
    /// omitted one on purpose) pass off a wrong read as a right one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("state key not covered by any supplied proof")]
    pub struct UnprovenKey;

    /// A sparse Merkle trie reconstructed purely from a set of
    /// [`InclusionProof`]s against one root — no database, no full trie,
    /// just whatever paths the supplied proofs actually cover. Lets a party
    /// holding only proofs (Part 3 Stage 3's bisection, or a light client)
    /// replay a state update and recompute the resulting root exactly the
    /// way `xc_storage::ArxiumDb::trie_root_after` would, checking the
    /// result against a post-state root someone else claims — without ever
    /// touching RocksDB or seeing the rest of the trie.
    ///
    /// Every proof handed to [`from_proofs`](Self::from_proofs) is verified
    /// against `root` before anything is recorded, so importing bad proofs
    /// can't corrupt the reconstructed shape — it just gets rejected.
    pub struct ProofBackedTrie {
        root: [u8; 32],
        // Internal-node hash -> its (left, right) children — the same
        // content `xc_storage::CF_MERKLE` would store for that node.
        nodes: std::collections::HashMap<[u8; 32], ([u8; 32], [u8; 32])>,
        // Leaf hash -> the value it commits to. Kept separately because a
        // leaf hash is one-way: `nodes` alone can't answer "what value does
        // this leaf hold", only "what are this internal node's children".
        leaves: std::collections::HashMap<[u8; 32], Vec<u8>>,
    }

    impl ProofBackedTrie {
        /// Rejects the whole batch if any single proof doesn't verify
        /// against `root` — a partially-bad proof set is exactly as
        /// untrustworthy as a wholly-bad one.
        pub fn from_proofs(root: [u8; 32], proofs: &[InclusionProof]) -> Result<Self, UnprovenKey> {
            let mut trie = Self { root, nodes: std::collections::HashMap::new(), leaves: std::collections::HashMap::new() };
            for proof in proofs {
                if !verify_proof(root, proof) {
                    // A proof that fails verification is indistinguishable,
                    // from this constructor's point of view, from one that
                    // was never supplied — either way the key ends up
                    // unproven.
                    return Err(UnprovenKey);
                }
                trie.record_path(proof);
            }
            Ok(trie)
        }

        /// Walks one verified proof's path bottom-up, recording every
        /// internal node's (left, right) pair (and the leaf's value, if
        /// any) — the same climb `verify_proof` does to recompute the root,
        /// just keeping the intermediate structure instead of discarding it.
        fn record_path(&mut self, proof: &InclusionProof) {
            let defaults = default_hashes();
            let mut current = match &proof.value {
                Some(value) => {
                    let leaf = leaf_hash(&proof.key_hash, value);
                    self.leaves.insert(leaf, value.clone());
                    leaf
                }
                None => defaults[0],
            };
            for level in (0..256).rev() {
                let sibling = proof.siblings[level];
                let (left, right) =
                    if bit_at(&proof.key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
                let parent = internal_hash(&left, &right);
                self.nodes.insert(parent, (left, right));
                current = parent;
            }
        }

        fn children(&self, hash: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), UnprovenKey> {
            self.nodes.get(hash).copied().ok_or(UnprovenKey)
        }

        /// Same shape as `xc_storage::ArxiumDb`'s private `descend` — walks
        /// `key_hash`'s 256-bit path from `self.root`, returning the sibling
        /// at each level and the node found at the leaf level. Fails closed
        /// (`UnprovenKey`) the instant the walk needs a node no supplied
        /// proof covers, rather than guessing.
        fn descend(&self, key_hash: &[u8; 32]) -> Result<([[u8; 32]; 256], [u8; 32]), UnprovenKey> {
            let defaults = default_hashes();
            let mut siblings = [[0u8; 32]; 256];
            let mut node = self.root;
            for level in 0..256 {
                let depth = 256 - level;
                if node == defaults[depth] {
                    siblings[level] = defaults[depth - 1];
                    node = defaults[depth - 1];
                } else {
                    let (left, right) = self.children(&node)?;
                    let (child, sibling) = if bit_at(key_hash, level) == 0 { (left, right) } else { (right, left) };
                    siblings[level] = sibling;
                    node = child;
                }
            }
            Ok((siblings, node))
        }

        /// The value proven for `key_hash` under the trie's current root —
        /// `Ok(None)` means proven absent, `Err(UnprovenKey)` means neither
        /// presence nor absence is known from what's been supplied.
        pub fn get(&self, key_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, UnprovenKey> {
            let (_, leaf_node) = self.descend(key_hash)?;
            if leaf_node == default_hashes()[0] {
                return Ok(None);
            }
            self.leaves.get(&leaf_node).cloned().map(Some).ok_or(UnprovenKey)
        }

        /// Updates `key_hash` to `new_value` (`None` deletes) and returns
        /// the new root — mirrors `xc_storage::ArxiumDb::trie_root_after`'s
        /// per-key descend-then-climb exactly, so replaying the same
        /// sequence of `apply` calls a real execution made produces the
        /// same root a real commit would, as long as every key touched was
        /// covered by a proof (directly, or via a node an earlier `apply`
        /// in this same trie already created).
        pub fn apply(&mut self, key_hash: [u8; 32], new_value: Option<Vec<u8>>) -> Result<[u8; 32], UnprovenKey> {
            let (siblings, _leaf) = self.descend(&key_hash)?;
            let defaults = default_hashes();
            let mut current = match &new_value {
                Some(value) => {
                    let leaf = leaf_hash(&key_hash, value);
                    self.leaves.insert(leaf, value.clone());
                    leaf
                }
                None => defaults[0],
            };
            for level in (0..256).rev() {
                let sibling = siblings[level];
                let (left, right) =
                    if bit_at(&key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
                let parent = internal_hash(&left, &right);
                self.nodes.insert(parent, (left, right));
                current = parent;
            }
            self.root = current;
            Ok(self.root)
        }

        pub fn root(&self) -> [u8; 32] {
            self.root
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn empty_trie_root_matches_the_all_default_path() {
            // A proof of non-inclusion for any key against the canonical
            // empty-trie root is just "every sibling is the matching default".
            let key_hash = hash_key(b"nonexistent");
            let defaults = default_hashes();
            let siblings: Vec<[u8; 32]> = (0..256).map(|level| defaults[255 - level]).collect();
            let proof = InclusionProof { key_hash, value: None, siblings };
            assert!(verify_proof(defaults[256], &proof));
        }

        #[test]
        fn a_tampered_value_fails_verification() {
            let key_hash = hash_key(b"k");
            let defaults = default_hashes();
            let value = b"v".to_vec();
            let leaf = leaf_hash(&key_hash, &value);
            let mut current = leaf;
            let mut siblings = vec![[0u8; 32]; 256];
            for level in (0..256).rev() {
                let sibling = defaults[255 - level];
                siblings[level] = sibling;
                let (left, right) = if bit_at(&key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
                current = internal_hash(&left, &right);
            }
            let root = current;
            let proof = InclusionProof { key_hash, value: Some(value), siblings };
            assert!(verify_proof(root, &proof));

            let tampered = InclusionProof { value: Some(b"different".to_vec()), ..proof };
            assert!(!verify_proof(root, &tampered));
        }

        #[test]
        fn wrong_sibling_count_is_rejected_rather_than_panicking() {
            let proof = InclusionProof { key_hash: [0u8; 32], value: None, siblings: vec![[0u8; 32]; 3] };
            assert!(!verify_proof([0u8; 32], &proof));
        }

        fn empty_trie_proof(key_hash: [u8; 32], value: Option<Vec<u8>>) -> InclusionProof {
            let defaults = default_hashes();
            InclusionProof { key_hash, value, siblings: (0..256).map(|level| defaults[255 - level]).collect() }
        }

        /// `ProofBackedTrie::apply` must land on exactly the root a real
        /// commit would — this is the property Part 3 Stage 3/4 rests on:
        /// a verifier with only proofs has to reach the same answer a node
        /// with the full trie would.
        #[test]
        fn apply_after_from_proofs_matches_a_hand_computed_root() {
            let key_hash = hash_key(b"account:arx1...");
            let empty_root = default_hashes()[256];
            let mut trie =
                ProofBackedTrie::from_proofs(empty_root, &[empty_trie_proof(key_hash, None)]).unwrap();

            let value = b"balance=100".to_vec();
            let new_root = trie.apply(key_hash, Some(value.clone())).unwrap();

            // Hand-compute the expected root: a single leaf, every sibling
            // on its path is the canonical empty-subtree hash.
            let defaults = default_hashes();
            let mut expected = leaf_hash(&key_hash, &value);
            for level in (0..256).rev() {
                let sibling = defaults[255 - level];
                let (left, right) =
                    if bit_at(&key_hash, level) == 0 { (expected, sibling) } else { (sibling, expected) };
                expected = internal_hash(&left, &right);
            }
            assert_eq!(new_root, expected);
            assert_eq!(trie.root(), expected);
            assert_eq!(trie.get(&key_hash).unwrap(), Some(value));
        }

        /// A key genuinely absent (proven so) reads back as `Ok(None)`, not
        /// an error — non-inclusion is a known fact, not a missing one.
        #[test]
        fn a_key_proven_absent_reads_as_none_not_an_error() {
            let key_hash = hash_key(b"never-written");
            let empty_root = default_hashes()[256];
            let trie = ProofBackedTrie::from_proofs(empty_root, &[empty_trie_proof(key_hash, None)]).unwrap();
            assert_eq!(trie.get(&key_hash).unwrap(), None);
        }

        /// A proof that doesn't verify against the claimed root must be
        /// rejected outright — importing it would poison the trie with
        /// nodes that don't actually chain up to `root`.
        #[test]
        fn from_proofs_rejects_a_proof_that_does_not_verify() {
            let key_hash = hash_key(b"k");
            let wrong_root = [0xAB; 32]; // not the real empty-trie root
            let err = ProofBackedTrie::from_proofs(wrong_root, &[empty_trie_proof(key_hash, None)]);
            assert!(err.is_err());
        }

        /// The fail-closed case that justifies this type's existence: two
        /// leaves share every bit of their path except the very last one, so
        /// proving key A necessarily exposes key B's leaf *hash* as a
        /// sibling along the way — but the trie never learns B's actual
        /// value (that's not part of A's proof), so a read of B must still
        /// fail closed rather than silently resolving from the exposed hash.
        #[test]
        fn a_sibling_leaf_exposed_by_another_proof_still_reads_as_unproven() {
            let key_hash_a = [0u8; 32];
            let mut key_hash_b = [0u8; 32];
            key_hash_b[31] = 1; // differs only in the last bit (level 255)

            let value_a = b"a".to_vec();
            let value_b = b"b".to_vec();
            let leaf_a = leaf_hash(&key_hash_a, &value_a);
            let leaf_b = leaf_hash(&key_hash_b, &value_b);
            let defaults = default_hashes();

            // Level 255: the only level at which a and b differ.
            let mut current = internal_hash(&leaf_a, &leaf_b);
            // Levels 254..0: a and b share every bit, so the sibling at
            // each of these levels is the untouched default subtree.
            for level in (0..255).rev() {
                let sibling = defaults[255 - level];
                let (left, right) =
                    if bit_at(&key_hash_a, level) == 0 { (current, sibling) } else { (sibling, current) };
                current = internal_hash(&left, &right);
            }
            let root = current;

            let mut siblings_a = vec![[0u8; 32]; 256];
            siblings_a[255] = leaf_b;
            for level in 0..255 {
                siblings_a[level] = defaults[255 - level];
            }
            let proof_a = InclusionProof { key_hash: key_hash_a, value: Some(value_a), siblings: siblings_a };
            assert!(verify_proof(root, &proof_a), "test setup: proof_a must be valid");

            let trie = ProofBackedTrie::from_proofs(root, &[proof_a]).unwrap();
            assert_eq!(
                trie.get(&key_hash_b),
                Err(UnprovenKey),
                "b's leaf hash is visible as a sibling, but its value was never proven"
            );
        }
    }
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
