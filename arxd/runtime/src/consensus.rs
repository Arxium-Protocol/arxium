// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_bls::BlsPublicKey;
use xc_circuit::{
    BlsKeyKey, EvidenceMarkerKey, GenesisHashKey, KvRead, StakeByValidatorKey, StakeKey,
};
use xc_executor::BlockUpdates;
use xc_primitives::Address;
use xc_storage::{BlsKeyRegistration, EvidenceMarker, StorageError};

use crate::staking::is_authorized;
use crate::{ChainAction, ChainBlock};

/// Validates BLS public-key bytes against their proof of possession and
/// returns the key sized.
///
/// Four call sites need this now (`RegisterBlsKey` and `JoinValidator`, each
/// in both the admission precheck and dispatch), and the rule is
/// consensus-relevant: rejecting malformed or off-curve bytes here rather than
/// at the first failed precommit verification later.
///
/// The PoP check is the load-bearing half. `PublicKey::validate()` alone —
/// which is all this used to do — accepts a rogue key
/// `pk_r = g^x · (∏ honest pk_i)^-1`, a perfectly valid group element whose
/// registrant can then forge a finality quorum certificate for an arbitrary
/// block at an arbitrary height, signed by validators who never voted (see
/// `xc_bls::verify_possession`). Every path that writes a key into the
/// registry must go through here, and genesis (`arxd/genesis`) enforces the
/// same rule for keys that arrive in the chain spec instead of via an action.
pub(crate) fn validated_bls_pubkey(pubkey: &[u8], pop: &[u8]) -> anyhow::Result<[u8; 48]> {
    let bytes: [u8; 48] = pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("BLS public key must be 48 bytes"))?;
    let pop: [u8; 96] = pop
        .try_into()
        .map_err(|_| anyhow::anyhow!("BLS proof of possession must be 96 bytes"))?;
    // Two distinct operator-facing errors: a mistyped/off-curve key is a
    // different mistake from a PoP that doesn't match a good key.
    xc_bls::verify_possession(&BlsPublicKey(bytes), &xc_bls::BlsSignature(pop)).map_err(|err| {
        match err {
            xc_bls::BlsError::InvalidPublicKey => anyhow::anyhow!("invalid BLS public key"),
            _ => anyhow::anyhow!("invalid BLS proof of possession"),
        }
    })?;
    Ok(bytes)
}

/// Proof that a validator signed two different blocks at the same
/// height — normally built and submitted by `xc_evidence::spawn_evidence_watcher`
/// when it observes a competing block, never hand-crafted by an
/// ordinary user. Anyone *could* submit one given the two blocks, but
/// `xc_evidence::verify_equivocation` is what actually gates the slash, not
/// who submitted it — so that's fine.
pub(crate) fn submit_equivocation_evidence<V: KvRead<Error = StorageError>>(
    view: &V,
    block_a: &ChainBlock,
    block_b: &ChainBlock,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let evidence = xc_evidence::EquivocationEvidence {
        block_a: block_a.clone(),
        block_b: block_b.clone(),
    };
    let equivocator = xc_evidence::verify_equivocation(&evidence)
        .map_err(|err| anyhow::anyhow!("invalid equivocation evidence: {err}"))?;
    if view
        .get(&EvidenceMarkerKey {
            height: block_a.height,
            proposer: &equivocator,
        })?
        .is_some()
    {
        anyhow::bail!(
            "equivocation evidence for {equivocator} at height {} already processed",
            block_a.height
        );
    }

    let masters = view
        .get(&StakeByValidatorKey(&equivocator))?
        .unwrap_or_default();
    let master = masters
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{equivocator} has no stake to slash for equivocation"))?;
    let allocation = view
        .get(&StakeKey {
            master: &master,
            validator: &equivocator,
        })?
        .ok_or_else(|| anyhow::anyhow!("{equivocator} has no active stake allocation to slash"))?;
    let total =
        allocation.active_amount + allocation.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);

    let (accounts, stakes) = circuit_staking::apply_slash(
        view,
        &equivocator,
        xc_evidence::slash_amount(total),
        circuit_staking::SlashReason::DoubleSign,
        current_height,
    )?;
    Ok(BlockUpdates {
        accounts,
        stakes,
        evidence: Some(EvidenceMarker {
            height: block_a.height,
            proposer: equivocator,
        }),
        ..Default::default()
    })
}

/// Submits a `Fault::ActionDivergence`/`Fault::BlockDivergence` evidence
/// artifact for adjudication and slashing — the counterpart to
/// `submit_equivocation_evidence` for the two fault kinds that can't name a
/// culprit from signatures/proofs alone and need chain-specific replay
/// (`crate::adjudicate`) instead. `Fault::Equivocation` artifacts are
/// rejected here — that kind goes through `SubmitEquivocationEvidence` with
/// the real blocks, not a JSON artifact.
///
/// `artifact.genesis_hash` is checked against this chain's own genesis hash
/// (`GenesisHashKey`) first: adjudication depends only on the artifact's
/// action bytes and proofs, so without this a validator running the same
/// keys on two Arxium chains could be slashed here for a fault committed on
/// the other one.
/// Genesis hashes are written both ways in this codebase — `0x`-prefixed in
/// artifacts (`core/evidence`), bare hex in some specs — so compare on the
/// hex itself, case-insensitively.
fn genesis_hash_matches(a: &str, b: &str) -> bool {
    let strip = |s: &str| s.strip_prefix("0x").unwrap_or(s).to_ascii_lowercase();
    strip(a) == strip(b)
}

pub(crate) fn submit_execution_fault<V: KvRead<Error = StorageError>>(
    view: &V,
    artifact_json: &str,
    current_height: u64,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    let artifact: xc_artifact::EvidenceArtifact = serde_json::from_str(artifact_json)
        .map_err(|err| anyhow::anyhow!("malformed evidence artifact JSON: {err}"))?;

    // Fail closed: a chain with no seeded genesis hash cannot tell its own
    // faults from another chain's, and slashing is not the place to guess.
    let chain_genesis = view.get(&GenesisHashKey)?.ok_or_else(|| {
        anyhow::anyhow!("this chain has no seeded genesis hash to check the artifact against")
    })?;
    if !genesis_hash_matches(&chain_genesis, &artifact.genesis_hash) {
        anyhow::bail!(
            "evidence artifact was produced against genesis {}, this chain's genesis is {chain_genesis}",
            artifact.genesis_hash,
        );
    }

    // `reason` rides along with the culprit because not every fault that
    // arrives here is an execution fault: a precommit equivocation is a
    // double-sign (whitepaper §9.3), and the slash record must say so.
    let (outcome, height, proposer_pubkey, voter_pubkey, reason) = match &artifact.fault {
        xc_artifact::Fault::ActionDivergence {
            proposer_pubkey,
            voter_pubkey,
            height,
            ..
        } => {
            let outcome = crate::adjudicate::adjudicate_action_divergence(&artifact)
                .map_err(|err| anyhow::anyhow!("adjudication failed: {err}"))?;
            (
                outcome,
                *height,
                proposer_pubkey.clone(),
                voter_pubkey.clone(),
                circuit_staking::SlashReason::ExecutionFault,
            )
        }
        xc_artifact::Fault::BlockDivergence {
            proposer_pubkey,
            voter_pubkey,
            height,
            ..
        } => {
            let outcome = crate::adjudicate::adjudicate_block_divergence(&artifact)
                .map_err(|err| anyhow::anyhow!("adjudication failed: {err}"))?;
            (
                outcome,
                *height,
                proposer_pubkey.clone(),
                voter_pubkey.clone(),
                circuit_staking::SlashReason::ExecutionFault,
            )
        }
        // No replay, no second party: two BLS signatures over two different
        // precommit messages at one height are the whole proof, so
        // `xc_artifact::verify` names the culprit outright — the same shape
        // `Fault::Equivocation` has, which is why this one can ride this
        // action instead of needing its own. `proposer_pubkey` is empty
        // because the fault has no proposer; the culpability match below
        // compares against it first and an empty string can never equal a
        // hex-encoded key.
        xc_artifact::Fault::PrecommitEquivocation {
            voter_pubkey,
            height,
            ..
        } => {
            let verdict = xc_artifact::verify(&artifact)
                .map_err(|err| anyhow::anyhow!("invalid precommit equivocation artifact: {err}"))?;
            let xc_artifact::Verdict::Culpable {
                culpable_pubkey, ..
            } = verdict
            else {
                anyhow::bail!("precommit equivocation did not name a culprit");
            };
            (
                crate::adjudicate::AdjudicationOutcome::Culpable { culpable_pubkey },
                *height,
                String::new(),
                voter_pubkey.clone(),
                circuit_staking::SlashReason::DoubleSign,
            )
        }
        xc_artifact::Fault::Equivocation { .. } => {
            anyhow::bail!(
                "Equivocation evidence must be submitted via SubmitEquivocationEvidence, not SubmitExecutionFault"
            );
        }
        // A plain signed assertion with no cryptographic culpability
        // resolution — there is nothing for `adjudicate::*` to replay.
        xc_artifact::Fault::ExecutionDisagreement { .. } => {
            anyhow::bail!("ExecutionDisagreement has no on-chain adjudication path");
        }
    };

    let culpable_pubkey = match outcome {
        crate::adjudicate::AdjudicationOutcome::Culpable { culpable_pubkey } => culpable_pubkey,
        crate::adjudicate::AdjudicationOutcome::Disagreement { reason } => {
            anyhow::bail!("adjudication could not name a culprit: {reason}");
        }
    };

    // The proposer signs with their Ed25519 chain key, so their pubkey
    // converts to an `Address` directly; the dissenting voter signs with
    // their BLS finality key, which must instead be resolved to the
    // `Address` it was registered under (`RegisterBlsKey`/`JoinValidator`) —
    // there is no direct BLS-pubkey-to-`Address` derivation.
    let culprit = if culpable_pubkey == proposer_pubkey {
        let bytes = hex::decode(
            proposer_pubkey
                .strip_prefix("0x")
                .unwrap_or(&proposer_pubkey),
        )?;
        Address::from_pubkey_bytes(&bytes)?
    } else if culpable_pubkey == voter_pubkey {
        let bytes = hex::decode(voter_pubkey.strip_prefix("0x").unwrap_or(&voter_pubkey))?;
        let bytes: [u8; 48] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("BLS public key must be 48 bytes"))?;
        bls_pubkey_owner_lookup(&BlsPublicKey(bytes))?
            .ok_or_else(|| anyhow::anyhow!("no registered owner for the culpable BLS pubkey"))?
    } else {
        anyhow::bail!("adjudicator named a pubkey that matches neither party in the artifact");
    };

    if view
        .get(&EvidenceMarkerKey {
            height,
            proposer: &culprit,
        })?
        .is_some()
    {
        anyhow::bail!(
            "execution fault evidence for {culprit} at height {height} already processed"
        );
    }

    let masters = view
        .get(&StakeByValidatorKey(&culprit))?
        .unwrap_or_default();
    let master = masters
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{culprit} has no stake to slash for an execution fault"))?;
    let allocation = view
        .get(&StakeKey {
            master: &master,
            validator: &culprit,
        })?
        .ok_or_else(|| anyhow::anyhow!("{culprit} has no active stake allocation to slash"))?;
    let total =
        allocation.active_amount + allocation.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);

    let (accounts, stakes) = circuit_staking::apply_slash(
        view,
        &culprit,
        xc_evidence::slash_amount(total),
        reason,
        current_height,
    )?;
    Ok(BlockUpdates {
        accounts,
        stakes,
        evidence: Some(EvidenceMarker {
            height,
            proposer: culprit,
        }),
        ..Default::default()
    })
}

/// Registers `validator`'s BLS pubkey for finality-certificate
/// precommit voting (`arxd/finality`). Any address may be registered —
/// the key is only meaningful once/if that address is also in the
/// validator set at some height; no membership check happens here.
pub(crate) fn register_bls_key<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    validator: &Address,
    pubkey: &[u8],
    pop: &[u8],
    current_height: u64,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    if !is_authorized(&action.sender, validator, operator_lookup)? {
        anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
    }
    let bytes = validated_bls_pubkey(pubkey, pop)?;
    if let Some(owner) = bls_pubkey_owner_lookup(&BlsPublicKey(bytes))?
        && &owner != validator
    {
        anyhow::bail!("BLS pubkey already registered to {owner}");
    }
    let previous_pubkey = view.get(&BlsKeyKey(validator))?;
    Ok(BlockUpdates {
        // Effective one block later, same delay as `ValidatorSetSnapshot` —
        // see `BlsKeyRegistration`'s doc comment.
        bls_key: Some(BlsKeyRegistration {
            address: validator.clone(),
            pubkey: xc_bls::BlsPublicKey(bytes),
            effective_height: current_height + 1,
            previous_pubkey,
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{ACTION_FEE, ActionPayload};
    use std::collections::HashMap;
    use xc_primitives::Action;

    fn signed_chain_block(
        key: &ed25519_dalek::SigningKey,
        height: u64,
        timestamp: u64,
    ) -> ChainBlock {
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: ChainBlock = xc_primitives::Block::genesis(timestamp);
        block.height = height;
        block.sign(addr, key);
        block
    }

    #[test]
    fn equivocation_evidence_slashes_the_equivocator() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let equivocator = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let block_a = signed_chain_block(&key, 5, 100);
        let block_b = signed_chain_block(&key, 5, 200);

        let sub_account = circuit_staking::stake_subaccount(&equivocator);
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (sub_account, funded(10_000)),
                (equivocator.clone(), funded(ACTION_FEE)),
            ]),
            HashMap::from([(
                (equivocator.clone(), equivocator.clone()),
                self_allocation(&equivocator, 10_000),
            )]),
        );
        view.put(
            &StakeByValidatorKey(&equivocator),
            &vec![equivocator.clone()],
        )
        .unwrap();
        let action = Action {
            sender: equivocator.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SubmitEquivocationEvidence {
                block_a: Box::new(block_a),
                block_b: Box::new(block_b),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &no_bls_owner,
        )
        .unwrap();

        // Whitepaper §9.3: double-sign slashes 100% of stake, so the
        // allocation nets to zero and is removed outright (`None`) rather
        // than left at a reduced balance.
        assert_eq!(xc_evidence::slash_amount(10_000), 10_000);
        let allocation = updates
            .stakes
            .allocations
            .get(&(equivocator.clone(), equivocator.clone()))
            .unwrap();
        assert!(allocation.is_none());
        let marker = updates.evidence.expect("must write an evidence marker");
        assert_eq!(marker.height, 5);
        assert_eq!(marker.proposer, equivocator);
    }

    #[test]
    fn precommit_equivocation_artifact_slashes_the_double_signer() {
        let voter = Address::from_pubkey_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let (sk, pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let precommit = |block_hash: &str| {
            let ep = [1u8; 32];
            xc_artifact::PrecommitAttestation {
                height: 5,
                block_hash: block_hash.to_string(),
                ep: format!("0x{}", hex::encode(ep)),
                signature: format!(
                    "0x{}",
                    hex::encode(
                        xc_bls::sign(
                            &sk,
                            &xc_artifact::precommit_signing_bytes(5, block_hash, &ep)
                        )
                        .0
                    )
                ),
            }
        };
        let artifact = xc_artifact::EvidenceArtifact {
            artifact_version: xc_artifact::ARTIFACT_VERSION,
            genesis_hash: "0xfeed".to_string(),
            fault: xc_artifact::Fault::PrecommitEquivocation {
                voter_pubkey: format!("0x{}", hex::encode(pk.0)),
                height: 5,
                precommits: [precommit("0xaaa"), precommit("0xbbb")],
            },
            human_readable: serde_json::json!({}),
        };

        let reporter = Address::from_pubkey_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let sub_account = circuit_staking::stake_subaccount(&voter);
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (sub_account, funded(10_000)),
                (reporter.clone(), funded(ACTION_FEE)),
            ]),
            HashMap::from([(
                (voter.clone(), voter.clone()),
                self_allocation(&voter, 10_000),
            )]),
        );
        view.put(&StakeByValidatorKey(&voter), &vec![voter.clone()])
            .unwrap();
        view.put(&GenesisHashKey, &"feed".to_string()).unwrap();

        // The culprit signs with a BLS key, which has no address derivation —
        // the registry lookup is the only way back to who gets slashed.
        let voter_for_lookup = voter.clone();
        let bls_owner = move |_: &BlsPublicKey| Ok(Some(voter_for_lookup.clone()));
        let action = Action {
            sender: reporter.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SubmitExecutionFault {
                artifact_json: serde_json::to_string(&artifact).unwrap(),
            },
        };
        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &bls_owner,
        )
        .unwrap();

        // Same full-stake slash as block equivocation (whitepaper §9.3):
        // the allocation is removed outright, not reduced.
        assert!(
            updates
                .stakes
                .allocations
                .get(&(voter.clone(), voter.clone()))
                .unwrap()
                .is_none()
        );
        let marker = updates.evidence.expect("must write an evidence marker");
        assert_eq!(marker.height, 5);
        assert_eq!(marker.proposer, voter);
    }

    #[test]
    fn equivocation_evidence_rejected_when_already_processed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let equivocator = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let block_a = signed_chain_block(&key, 5, 100);
        let block_b = signed_chain_block(&key, 5, 200);

        let db = temp_db();
        let mut view = seeded_view(&db, HashMap::new(), HashMap::new());
        view.put(
            &EvidenceMarkerKey {
                height: 5,
                proposer: &equivocator,
            },
            &(),
        )
        .unwrap();
        let action = Action {
            sender: equivocator.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SubmitEquivocationEvidence {
                block_a: Box::new(block_a),
                block_b: Box::new(block_b),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already processed"));
    }

    #[test]
    fn register_bls_key_accepts_a_valid_pubkey() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (sk, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::new(),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
                pop: xc_bls::prove_possession(&sk).0.to_vec(),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
        )
        .unwrap();
        let registration = updates.bls_key.expect("expected a bls_key update");
        assert_eq!(registration.address, alice);
        assert_eq!(registration.pubkey.0, pubkey.0);
    }

    #[test]
    fn register_bls_key_rejects_a_pubkey_already_held_by_a_different_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let (sk, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::new(),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
                pop: xc_bls::prove_possession(&sk).0.to_vec(),
            },
        };
        let owned_by_bob = |_: &BlsPublicKey| Ok(Some(bob.clone()));

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &owned_by_bob,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_bls_key_allows_re_registering_your_own_already_held_pubkey() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (sk, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::new(),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
                pop: xc_bls::prove_possession(&sk).0.to_vec(),
            },
        };
        let owned_by_self = |_: &BlsPublicKey| Ok(Some(alice.clone()));

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &owned_by_self,
        )
        .expect("re-registering your own key should stay a no-op success");
        assert_eq!(
            updates.bls_key.expect("expected a bls_key update").address,
            alice
        );
    }

    #[test]
    fn register_bls_key_rejects_malformed_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::new(), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: vec![0u8; 48],
                pop: vec![0u8; 96],
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid BLS public key"));
    }

    /// The rogue-key gate. A key nobody can produce a signature under is
    /// still a valid group element, so `PublicKey::validate()` — the whole
    /// of the old check — waves it through; the holder of
    /// `pk_r = g^x · (∏ honest pk_i)^-1` can then forge a quorum
    /// certificate for any block at any height, signed by validators who
    /// never voted (see `xc_bls::verify_possession`). What such a key can
    /// never come with is a proof of possession, which is what this
    /// rejects: a well-formed, on-curve, unowned key whose PoP is another
    /// key's.
    #[test]
    fn register_bls_key_rejects_a_well_formed_key_with_someone_elses_proof_of_possession() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::new(),
        );
        let (_, unowned) = xc_bls::keygen_from_seed(&[21u8; 32]).unwrap();
        let (other_sk, _) = xc_bls::keygen_from_seed(&[22u8; 32]).unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: unowned.0.to_vec(),
                pop: xc_bls::prove_possession(&other_sk).0.to_vec(),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid BLS proof of possession"),
            "expected a PoP rejection, got {err}"
        );
    }

    /// The artifact is only parsed, never adjudicated, before the genesis
    /// check runs — so an `equivocation` artifact (which
    /// `submit_execution_fault` rejects on its own grounds) is enough to see
    /// which rejection comes first, and that the check exists at all.
    fn attestation() -> serde_json::Value {
        serde_json::json!({
            "header": {
                "height": 1,
                "parent_hash": "",
                "timestamp": 0,
                "tx_root": "0x00",
                "proposer": "",
                "state_root": "",
                "round": 0,
            },
            "signature": "0x00",
        })
    }

    fn foreign_artifact_json(genesis_hash: &str) -> String {
        serde_json::json!({
            "artifact_version": xc_artifact::ARTIFACT_VERSION,
            "genesis_hash": genesis_hash,
            "fault": "equivocation",
            "proposer_pubkey": "0x00",
            "height": 1,
            "blocks": [attestation(), attestation()],
            "human_readable": serde_json::Value::Null,
        })
        .to_string()
    }

    #[test]
    fn execution_fault_from_another_chain_is_rejected() {
        let db = temp_db();
        let mut view = seeded_view(&db, HashMap::new(), HashMap::new());
        view.put(&GenesisHashKey, &"0xaaaa".to_string()).unwrap();
        let no_bls_owner = |_: &BlsPublicKey| -> Result<Option<Address>, StorageError> { Ok(None) };

        let err = submit_execution_fault(&view, &foreign_artifact_json("0xbbbb"), 1, &no_bls_owner)
            .unwrap_err();
        assert!(err.to_string().contains("0xbbbb"), "{err}");

        // Same artifact, this chain's genesis (and the `0x`/case spelling
        // artifacts actually use): the genesis check is out of the way and
        // the fault kind itself is what rejects it.
        let err = submit_execution_fault(&view, &foreign_artifact_json("0xAAAA"), 1, &no_bls_owner)
            .unwrap_err();
        assert!(
            err.to_string().contains("SubmitEquivocationEvidence"),
            "{err}"
        );
    }

    #[test]
    fn execution_fault_is_rejected_on_a_chain_with_no_seeded_genesis_hash() {
        let db = temp_db();
        let view = seeded_view(&db, HashMap::new(), HashMap::new());
        let no_bls_owner = |_: &BlsPublicKey| -> Result<Option<Address>, StorageError> { Ok(None) };

        let err = submit_execution_fault(&view, &foreign_artifact_json("0xaaaa"), 1, &no_bls_owner)
            .unwrap_err();
        assert!(err.to_string().contains("no seeded genesis hash"), "{err}");
    }
}
