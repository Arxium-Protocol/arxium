// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Payload-aware re-execution adjudicator for `Fault::ActionDivergence` —
//! the first thing in `arx-verify` that isn't chain-agnostic (feature-gated
//! for exactly that reason; see the crate's `Cargo.toml`).
//!
//! `xc_artifact::verify()` can confirm an `ActionDivergence` artifact is
//! well-formed (both claims are validly signed, their proofs verify against
//! their own `pre_state_root`s, and the post-roots genuinely differ) but it
//! can't say *who's* wrong — that means decoding `action_bytes` as
//! CoreChain's `ActionPayload` and replaying it, which is what this module
//! does.
//!
//! ## Coverage
//!
//! This replays the action against a [`ProofBackedView`] — a `KvRead`
//! populated purely from the claim's proofs, no database — by calling the
//! real `arxd_runtime::dispatch`, not a reimplementation. That reuse is
//! also what limits coverage: `dispatch` reads several things outside the
//! Merkle state trie entirely (`compute_state_root` only ever covers
//! `CF_ACCOUNTS`/`CF_VALIDATORS`(-balances)/`CF_ASSETS`/`CF_ATTESTORS`
//! balances — see `xc_storage::is_state_key`), and those reads have no
//! proof to check them against:
//!
//! - Operator authorization (`AuthorizeOperator`/`RevokeOperator`, and the
//!   delegated-management path of `JoinValidator`/`LeaveValidator`/
//!   `RegisterBlsKey`) lives in `CF_META`.
//! - BLS-key ownership (`JoinValidator`/`RegisterBlsKey`) lives in `CF_META`.
//! - The equivocation-processed marker (`SubmitEquivocationEvidence`) lives
//!   in `CF_META`.
//! - The governor key (`RegisterAttestor`/`DeregisterAttestor`) and the
//!   asset registry entry (`RegisterAsset`/`IssueAsset`/`TransferAsset`,
//!   via `AssetKey`) both live in `CF_META` too — only asset *balances*
//!   (`AssetBalanceKey`) are Merkleized.
//! - `LeaveValidator` additionally needs the current validator set, passed
//!   into `dispatch` as a plain slice rather than read through `KvRead` —
//!   there's no proof shape for "this is the answer to a parameter", only
//!   for a key read, so this is out of reach the same way.
//!
//! That leaves `Transfer`, `Stake`, `Unstake`, `VerifyIdentityCredential`,
//! `GrantAttestation`, and `RevokeAttestation` as the variants this can
//! actually resolve to `Culpable`. Everything else — reached at all, or
//! hitting one of the reads above — resolves to `Disagreement`, same as
//! `xc_artifact::verify()` alone would say. This is a real, load-bearing
//! decision (not a stopgap TODO): extending it means Merkleizing more state
//! (a schema change, like the `CF_ASSETS`/`CF_ATTESTORS` bumps already in
//! this codebase's history), not writing more code here.

use xc_artifact::{ActionClaim, EvidenceArtifact, Fault};
use xc_circuit::{AccountKey, AssetBalanceKey, AttestorRecordKey, KeySpec, KvRead, StakeByValidatorKey, StakeKey};
use xc_executor::BlockUpdates;
use xc_poe::state_trie::{InclusionProof, ProofBackedTrie};
use xc_primitives::Address;
use xc_storage::StorageError;

#[derive(Debug, thiserror::Error)]
pub enum AdjudicateError {
    #[error("not an ActionDivergence fault")]
    WrongFaultKind,
    #[error("artifact does not verify: {0}")]
    InvalidArtifact(#[from] xc_artifact::VerifyError),
    #[error("malformed hex in artifact: {0}")]
    BadHex(#[from] hex::FromHexError),
    #[error("action_bytes does not decode as a CoreChain action: {0}")]
    BadAction(String),
    #[error("state root is not well-formed: {0}")]
    BadRoot(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationOutcome {
    /// Re-execution names a culprit: whichever party's claimed
    /// `post_state_root` doesn't match what replaying the action actually
    /// produces.
    Culpable { culpable_pubkey: String },
    /// Re-execution couldn't resolve this one way or the other — either the
    /// action needed a read outside what's provable (see module doc), or
    /// (which should never happen for two claims that already passed
    /// `xc_artifact::verify()`'s consistency checks) both sides turned out
    /// to be wrong.
    Disagreement { reason: String },
}

/// Re-executes the disputed action against each claim's own proven
/// pre-state and compares the result to what each side claimed. Returns
/// `Ok` even when the outcome is `Disagreement` — that's not a failure of
/// this function, it's this function correctly declining to guess. `Err` is
/// reserved for a structurally invalid artifact (should already have been
/// caught by `xc_artifact::verify()`, called internally first).
pub fn adjudicate_action_divergence(artifact: &EvidenceArtifact) -> Result<AdjudicationOutcome, AdjudicateError> {
    xc_artifact::verify(artifact)?;
    let Fault::ActionDivergence {
        proposer_pubkey,
        voter_pubkey,
        height,
        action_index,
        action_bytes,
        proposed_claim,
        dissent_claim,
    } = &artifact.fault
    else {
        return Err(AdjudicateError::WrongFaultKind);
    };
    let _ = action_index; // bound into the claims' signatures, already checked by verify()

    let action_bytes = hex::decode(action_bytes.strip_prefix("0x").unwrap_or(action_bytes))?;
    let config = bincode::config::standard();
    let (action, _): (arxd_runtime::ChainAction, usize) =
        bincode::serde::decode_from_slice(&action_bytes, config)
            .map_err(|err| AdjudicateError::BadAction(err.to_string()))?;

    let proposed_result = replay(&action, proposed_claim, *height)?;
    let dissent_result = replay(&action, dissent_claim, *height)?;

    match (proposed_result, dissent_result) {
        (ReplayResult::Unprovable(reason), _) | (_, ReplayResult::Unprovable(reason)) => {
            Ok(AdjudicationOutcome::Disagreement { reason })
        }
        (ReplayResult::Root(proposed_actual), ReplayResult::Root(dissent_actual)) => {
            let proposed_matches = proposed_actual == decode_root(&proposed_claim.post_state_root)?;
            let dissent_matches = dissent_actual == decode_root(&dissent_claim.post_state_root)?;
            match (proposed_matches, dissent_matches) {
                (true, false) => Ok(AdjudicationOutcome::Culpable { culpable_pubkey: voter_pubkey.clone() }),
                (false, true) => Ok(AdjudicationOutcome::Culpable { culpable_pubkey: proposer_pubkey.clone() }),
                (true, true) => Ok(AdjudicationOutcome::Disagreement {
                    reason: "both parties' claimed post-state roots are independently reproducible — \
                             the divergence isn't in this action's execution"
                        .to_string(),
                }),
                (false, false) => Ok(AdjudicationOutcome::Disagreement {
                    reason: "neither party's claimed post-state root matches independent re-execution — \
                             re-check the claimed pre-state, this shouldn't happen for a well-formed artifact"
                        .to_string(),
                }),
            }
        }
    }
}

enum ReplayResult {
    Root([u8; 32]),
    Unprovable(String),
}

fn decode_root(root: &str) -> Result<[u8; 32], AdjudicateError> {
    let bytes = hex::decode(root.strip_prefix("0x").unwrap_or(root))?;
    bytes.as_slice().try_into().map_err(|_| AdjudicateError::BadRoot(root.to_string()))
}

fn decode_proofs(claim: &ActionClaim) -> Result<Vec<InclusionProof>, AdjudicateError> {
    claim
        .proofs
        .iter()
        .map(|p| {
            let key_hash = hex::decode(p.key_hash.strip_prefix("0x").unwrap_or(&p.key_hash))?;
            let key_hash: [u8; 32] =
                key_hash.as_slice().try_into().map_err(|_| AdjudicateError::BadRoot(p.key_hash.clone()))?;
            let value = p.value.as_deref().map(|v| hex::decode(v.strip_prefix("0x").unwrap_or(v))).transpose()?;
            let siblings = p
                .siblings
                .iter()
                .map(|s| {
                    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s))?;
                    bytes.as_slice().try_into().map_err(|_| AdjudicateError::BadRoot(s.clone()))
                })
                .collect::<Result<Vec<[u8; 32]>, AdjudicateError>>()?;
            Ok(InclusionProof { key_hash, value, siblings })
        })
        .collect()
}

/// Replays `action` against `claim`'s proven pre-state and returns the
/// resulting root, or `Unprovable` the moment the replay needs anything
/// outside what a proof can cover (see module doc for the full list).
/// `height` is `Fault::ActionDivergence.height` — the same height both
/// claims' signatures are bound to — threaded straight into `dispatch`
/// since `Stake`/`Unstake`'s unbonding math depends on the real value, not
/// a placeholder.
fn replay(action: &arxd_runtime::ChainAction, claim: &ActionClaim, height: u64) -> Result<ReplayResult, AdjudicateError> {
    // `LeaveValidator` needs the live validator set as a plain parameter,
    // not a `KvRead` lookup — there's no proof shape for that, so this is
    // the one variant checked before even trying to build a view.
    if matches!(action.payload, arxd_runtime::ActionPayload::LeaveValidator { .. }) {
        return Ok(ReplayResult::Unprovable(
            "LeaveValidator depends on the live validator set, which isn't provable as a single key".to_string(),
        ));
    }

    let pre_root = decode_root(&claim.pre_state_root)?;
    let proofs = decode_proofs(claim)?;
    let trie = match ProofBackedTrie::from_proofs(pre_root, &proofs) {
        Ok(trie) => trie,
        Err(_) => return Ok(ReplayResult::Unprovable("a supplied proof does not verify".to_string())),
    };
    let view = ProofBackedView { trie };

    let fail_closed = |_: &Address| -> Result<Option<Address>, StorageError> { Err(StorageError::UnprovenRead) };
    let fail_closed_list = |_: &Address| -> Result<Vec<Address>, StorageError> { Err(StorageError::UnprovenRead) };
    let fail_closed_evidence = |_: u64, _: &Address| -> Result<bool, StorageError> { Err(StorageError::UnprovenRead) };
    let fail_closed_bls =
        |_: &xc_bls::BlsPublicKey| -> Result<Option<Address>, StorageError> { Err(StorageError::UnprovenRead) };

    let updates = arxd_runtime::dispatch(
        action,
        &view,
        &fail_closed,
        &fail_closed_list,
        &[],
        height,
        &fail_closed_evidence,
        &fail_closed_bls,
    );

    let updates = match updates {
        Ok(updates) => updates,
        Err(err) => {
            return match err.downcast_ref::<StorageError>() {
                Some(StorageError::UnprovenRead) => {
                    Ok(ReplayResult::Unprovable(format!("this action's dispatch needs unprovable state: {err}")))
                }
                // A real, deterministic rejection (bad nonce, insufficient
                // balance, ...) — both an honest proposer and an honest
                // dissenter would compute the same rejection, so this is
                // legitimate re-execution output, not a proof gap. A
                // rejected action never lands (dropped by `execute_actions`,
                // fee included — `charge_action_fee` only runs after
                // `dispatch_inner` succeeds), so the correct resulting root
                // is simply the unchanged pre-state root.
                _ => Ok(ReplayResult::Root(pre_root)),
            };
        }
    };

    let mut trie = view.trie;
    for (key, value) in state_entries(&updates) {
        match trie.apply(xc_poe::state_trie::hash_key(&key), value) {
            Ok(_) => {}
            Err(_) => return Ok(ReplayResult::Unprovable("the update touches a key outside the proven set".to_string())),
        }
    }
    Ok(ReplayResult::Root(trie.root()))
}

/// Flattens the parts of `BlockUpdates` that land in the Merkle state trie
/// (see `xc_storage::is_state_key`) into raw-key/new-value pairs, mirroring
/// `execute_actions`'s own `inter_action_roots` overlay construction
/// (`core/executor/src/lib.rs`) — everything else in `BlockUpdates`
/// (`validator_change`, `evidence`, `bls_key`, `operator`,
/// `asset_registration`) lives in `CF_META` and never touches the root, so
/// there's nothing to `apply` for it here.
fn state_entries(updates: &BlockUpdates) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let config = bincode::config::standard();
    let mut entries = Vec::new();
    for (address, entry) in &updates.accounts.0 {
        let value = bincode::serde::encode_to_vec(entry, config).expect("AccountEntry always encodes");
        entries.push((AccountKey(address).encode(), Some(value)));
    }
    for ((master, validator), allocation) in &updates.stakes.allocations {
        let key = StakeKey { master, validator }.encode();
        let value = allocation
            .as_ref()
            .map(|a| bincode::serde::encode_to_vec(a, config).expect("StakeAllocation always encodes"));
        entries.push((key, value));
    }
    for (validator, masters) in &updates.stakes.validator_index {
        let key = StakeByValidatorKey(validator).encode();
        let value = if masters.is_empty() {
            None
        } else {
            Some(bincode::serde::encode_to_vec(masters, config).expect("Vec<Address> always encodes"))
        };
        entries.push((key, value));
    }
    for ((asset_id, owner), balance) in &updates.assets.0 {
        let key = AssetBalanceKey { asset_id, owner }.encode();
        let value = bincode::serde::encode_to_vec(balance, config).expect("u128 always encodes");
        entries.push((key, Some(value)));
    }
    if let Some(registration) = &updates.attestor_registration {
        let key = AttestorRecordKey(&registration.attestor).encode();
        let value = bincode::serde::encode_to_vec(&registration.record, config).expect("AttestorRecord always encodes");
        entries.push((key, Some(value)));
    }
    if let Some(deregistration) = &updates.attestor_deregistration {
        entries.push((AttestorRecordKey(&deregistration.0).encode(), None));
    }
    entries
}

/// `KvRead` backed purely by a [`ProofBackedTrie`] — no database. Fails
/// closed (`StorageError::UnprovenRead`) for any key outside the four
/// Merkleized CFs *before* even consulting the trie: a `CF_META` key was
/// never inserted into the real trie to begin with, so a proof-backed trie
/// answering `Ok(None)` for one would be indistinguishable from a genuine
/// non-inclusion proof — see `xc_storage::is_state_key`'s doc comment.
struct ProofBackedView {
    trie: ProofBackedTrie,
}

impl KvRead for ProofBackedView {
    type Error = StorageError;

    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, StorageError> {
        let raw_key = key.encode();
        if !xc_storage::is_state_key(&raw_key) {
            return Err(StorageError::UnprovenRead);
        }
        let key_hash = xc_poe::state_trie::hash_key(&raw_key);
        match self.trie.get(&key_hash) {
            Ok(Some(bytes)) => {
                let config = bincode::config::standard();
                let (value, _) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(_unproven) => Err(StorageError::UnprovenRead),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;
    use xc_artifact::{StateProof, ARTIFACT_VERSION};
    use xc_storage::{AccountUpdates, ArxiumDb};

    fn temp_db() -> ArxiumDb {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-core-adjudicate-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        ArxiumDb::open(&dir).expect("open test db")
    }

    fn entry(balance: u128) -> xc_primitives::AccountEntry {
        xc_primitives::AccountEntry { balance, nonce: 0, identity_hash: None, zk_identity_verified: false, attested_by: None }
    }

    fn hex_proof(proof: xc_poe::state_trie::InclusionProof) -> StateProof {
        StateProof {
            key_hash: format!("0x{}", hex::encode(proof.key_hash)),
            value: proof.value.map(|v| format!("0x{}", hex::encode(v))),
            siblings: proof.siblings.iter().map(|s| format!("0x{}", hex::encode(s))).collect(),
        }
    }

    fn no_bls_owner(_: &xc_bls::BlsPublicKey) -> Result<Option<Address>, StorageError> {
        Ok(None)
    }
    fn no_operator(_: &Address) -> Result<Option<Address>, StorageError> {
        Ok(None)
    }
    fn no_operator_validators(_: &Address) -> Result<Vec<Address>, StorageError> {
        Ok(Vec::new())
    }
    fn evidence_never_processed(_: u64, _: &Address) -> Result<bool, StorageError> {
        Ok(false)
    }

    /// Builds a real `Transfer` dispute: alice sends bob 40, funded via a
    /// real `ArxiumDb` so the proofs and roots are genuine, not hand-waved.
    /// `dissent_amount` lets a test claim the dissenter computed a
    /// different (wrong) transfer amount, producing a different post-root.
    struct Scenario {
        artifact: EvidenceArtifact,
        voter_pubkey: String,
    }

    fn build_scenario(dissent_amount: u128) -> Scenario {
        let db = temp_db();
        let proposer_key = SigningKey::from_bytes(&[7u8; 32]);
        let alice = xc_primitives::Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = xc_primitives::Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        db.write_batch(&AccountUpdates(std::collections::BTreeMap::from([
            (alice.clone(), entry(1_000_000_000)),
            (bob.clone(), entry(0)),
        ])))
        .unwrap();
        let pre_root = db.compute_state_root(&[]).unwrap();

        let action: arxd_runtime::ChainAction = xc_primitives::Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: arxd_runtime::ActionPayload::Transfer { to: bob.clone(), amount: 40 },
        };
        let action_bytes = bincode::serde::encode_to_vec(&action, bincode::config::standard()).unwrap();

        // The real result, for the honest (proposer's) side.
        let view = xc_storage::BlockView::new(&db);
        let real_updates = arxd_runtime::dispatch(
            &action,
            &view,
            &no_operator,
            &no_operator_validators,
            &[],
            0,
            &evidence_never_processed,
            &no_bls_owner,
        )
        .unwrap();
        db.write_batch(&real_updates.accounts).unwrap();
        let real_post_root = db.compute_state_root(&[]).unwrap();

        // The dissenter's claimed result: same mechanics, but a possibly
        // different amount, computed against a *separate* copy of the
        // pre-state so it doesn't disturb `db`'s already-committed real one.
        let dissent_db = temp_db();
        dissent_db
            .write_batch(&AccountUpdates(std::collections::BTreeMap::from([
                (alice.clone(), entry(1_000_000_000)),
                (bob.clone(), entry(0)),
            ])))
            .unwrap();
        let dissent_action: arxd_runtime::ChainAction = xc_primitives::Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: arxd_runtime::ActionPayload::Transfer { to: bob.clone(), amount: dissent_amount },
        };
        let dissent_view = xc_storage::BlockView::new(&dissent_db);
        let dissent_updates = arxd_runtime::dispatch(
            &dissent_action,
            &dissent_view,
            &no_operator,
            &no_operator_validators,
            &[],
            0,
            &evidence_never_processed,
            &no_bls_owner,
        )
        .unwrap();
        dissent_db.write_batch(&dissent_updates.accounts).unwrap();
        let dissent_post_root = dissent_db.compute_state_root(&[]).unwrap();

        let alice_key = format!("account:{alice}").into_bytes();
        let bob_key = format!("account:{bob}").into_bytes();
        let proofs = vec![
            hex_proof(db.prove(&alice_key, &pre_root).unwrap()),
            hex_proof(db.prove(&bob_key, &pre_root).unwrap()),
        ];

        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let action_bytes_hash: [u8; 32] = sha2::Sha256::digest(&action_bytes).into();
        let height = 5u64;
        let action_index = 0u64;

        let proposed_msg = xc_artifact::action_claim_signing_bytes(
            height, action_index, &action_bytes_hash, &pre_root, &real_post_root,
        );
        let proposed_claim = ActionClaim {
            pre_state_root: pre_root.clone(),
            post_state_root: real_post_root,
            proofs: proofs.clone(),
            signature: format!("0x{}", hex::encode(proposer_key.sign(&proposed_msg).to_bytes())),
        };

        let dissent_msg = xc_artifact::action_claim_signing_bytes(
            height, action_index, &action_bytes_hash, &pre_root, &dissent_post_root,
        );
        let dissent_claim = ActionClaim {
            pre_state_root: pre_root,
            post_state_root: dissent_post_root,
            proofs,
            signature: format!("0x{}", hex::encode(xc_bls::sign(&voter_sk, &dissent_msg).0)),
        };

        let proposer_pubkey = format!("0x{}", hex::encode(proposer_key.verifying_key().as_bytes()));
        let voter_pubkey = format!("0x{}", hex::encode(voter_pk.0));

        Scenario {
            artifact: EvidenceArtifact {
                artifact_version: ARTIFACT_VERSION,
                genesis_hash: "0xgenesis".to_string(),
                fault: Fault::ActionDivergence {
                    proposer_pubkey,
                    voter_pubkey: voter_pubkey.clone(),
                    height,
                    action_index,
                    action_bytes: format!("0x{}", hex::encode(&action_bytes)),
                    proposed_claim,
                    dissent_claim,
                },
                human_readable: serde_json::json!({}),
            },
            voter_pubkey,
        }
    }

    /// The load-bearing end-to-end case: a dissenter who claims the wrong
    /// transfer amount is named culpable, using proofs and roots built from
    /// a real `ArxiumDb` — not hand-computed fixtures.
    #[test]
    fn a_dissenter_with_a_wrong_claimed_amount_is_named_culpable() {
        let scenario = build_scenario(999); // dissenter claims a different amount than really happened
        let outcome = adjudicate_action_divergence(&scenario.artifact).unwrap();
        assert_eq!(outcome, AdjudicationOutcome::Culpable { culpable_pubkey: scenario.voter_pubkey });
    }

    /// Both sides computing the identical (correct) result isn't actually
    /// possible to construct as an `ActionDivergence` artifact —
    /// `xc_artifact::verify()` itself rejects equal post-state roots as "not
    /// a divergence" before this module ever runs, which this asserts.
    #[test]
    fn identical_claims_are_rejected_before_reaching_the_adjudicator() {
        let scenario = build_scenario(40); // same amount as the real transfer
        let err = adjudicate_action_divergence(&scenario.artifact).unwrap_err();
        assert!(matches!(err, AdjudicateError::InvalidArtifact(_)));
    }

    /// `JoinValidator`'s dispatch always needs `bls_pubkey_owner_lookup` —
    /// unprovable by construction (see module doc) — so this must resolve
    /// to `Disagreement`, never a guessed `Culpable`.
    #[test]
    fn an_unprovable_action_type_resolves_to_disagreement_not_a_guess() {
        let alice = xc_primitives::Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        db.write_batch(&AccountUpdates(std::collections::BTreeMap::from([(alice.clone(), entry(1_000_000_000))])))
            .unwrap();
        let pre_root = db.compute_state_root(&[]).unwrap();

        let action: arxd_runtime::ChainAction = xc_primitives::Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: arxd_runtime::ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: arxd_runtime::MIN_VALIDATOR_STAKE,
                bls_pubkey: {
                    let (_sk, pk) = xc_bls::keygen_from_seed(&[50u8; 32]).unwrap();
                    pk.0.to_vec()
                },
            },
        };
        let action_bytes = bincode::serde::encode_to_vec(&action, bincode::config::standard()).unwrap();
        let action_bytes_hash: [u8; 32] = sha2::Sha256::digest(&action_bytes).into();

        let alice_key = format!("account:{alice}").into_bytes();
        let proofs = vec![hex_proof(db.prove(&alice_key, &pre_root).unwrap())];

        let proposer_key = SigningKey::from_bytes(&[7u8; 32]);
        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        // Two different (fabricated, since this can never actually resolve)
        // post-roots — only their difference matters, to pass verify()'s
        // "must actually diverge" check.
        let fake_post_a = format!("0x{}", hex::encode([0xAAu8; 32]));
        let fake_post_b = format!("0x{}", hex::encode([0xBBu8; 32]));
        let height = 5u64;
        let action_index = 0u64;

        let proposed_msg =
            xc_artifact::action_claim_signing_bytes(height, action_index, &action_bytes_hash, &pre_root, &fake_post_a);
        let dissent_msg =
            xc_artifact::action_claim_signing_bytes(height, action_index, &action_bytes_hash, &pre_root, &fake_post_b);

        let artifact = EvidenceArtifact {
            artifact_version: ARTIFACT_VERSION,
            genesis_hash: "0xgenesis".to_string(),
            fault: Fault::ActionDivergence {
                proposer_pubkey: format!("0x{}", hex::encode(proposer_key.verifying_key().as_bytes())),
                voter_pubkey: format!("0x{}", hex::encode(voter_pk.0)),
                height,
                action_index,
                action_bytes: format!("0x{}", hex::encode(&action_bytes)),
                proposed_claim: ActionClaim {
                    pre_state_root: pre_root.clone(),
                    post_state_root: fake_post_a,
                    proofs: proofs.clone(),
                    signature: format!("0x{}", hex::encode(proposer_key.sign(&proposed_msg).to_bytes())),
                },
                dissent_claim: ActionClaim {
                    pre_state_root: pre_root,
                    post_state_root: fake_post_b,
                    proofs,
                    signature: format!("0x{}", hex::encode(xc_bls::sign(&voter_sk, &dissent_msg).0)),
                },
            },
            human_readable: serde_json::json!({}),
        };

        let outcome = adjudicate_action_divergence(&artifact).unwrap();
        assert!(matches!(outcome, AdjudicationOutcome::Disagreement { .. }));
    }
}
