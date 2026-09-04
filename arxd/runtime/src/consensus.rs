// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_bls::BlsPublicKey;
use xc_circuit::{KvRead, StakeByValidatorKey, StakeKey};
use xc_executor::BlockUpdates;
use xc_primitives::Address;
use xc_storage::{BlsKeyRegistration, EvidenceMarker, StorageError};

use crate::{ChainAction, ChainBlock};
use crate::staking::is_authorized;

/// Validates BLS public-key bytes and returns them sized.
///
/// Four call sites need this now (`RegisterBlsKey` and `JoinValidator`, each
/// in both the admission precheck and dispatch), and the rule is
/// consensus-relevant: rejecting malformed or off-curve bytes here rather than
/// at the first failed precommit verification later.
pub(crate) fn validated_bls_pubkey(pubkey: &[u8]) -> anyhow::Result<[u8; 48]> {
    blst::min_pk::PublicKey::from_bytes(pubkey)
        .and_then(|pk| pk.validate())
        .map_err(|_| anyhow::anyhow!("invalid BLS public key"))?;
    pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("BLS public key must be 48 bytes"))
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
    evidence_processed: &dyn Fn(u64, &Address) -> Result<bool, StorageError>,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let evidence = xc_evidence::EquivocationEvidence {
        block_a: block_a.clone(),
        block_b: block_b.clone(),
    };
    let equivocator = xc_evidence::verify_equivocation(&evidence)
        .map_err(|err| anyhow::anyhow!("invalid equivocation evidence: {err}"))?;
    if evidence_processed(block_a.height, &equivocator)? {
        anyhow::bail!(
            "equivocation evidence for {equivocator} at height {} already processed",
            block_a.height
        );
    }

    let masters = view.get(&StakeByValidatorKey(&equivocator))?.unwrap_or_default();
    let master = masters.first().cloned().ok_or_else(|| {
        anyhow::anyhow!("{equivocator} has no stake to slash for equivocation")
    })?;
    let allocation = view
        .get(&StakeKey { master: &master, validator: &equivocator })?
        .ok_or_else(|| anyhow::anyhow!("{equivocator} has no active stake allocation to slash"))?;
    let total = allocation.active_amount
        + allocation.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);

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

/// Registers `validator`'s BLS pubkey for finality-certificate
/// precommit voting (`arxd/finality`). Any address may be registered —
/// the key is only meaningful once/if that address is also in the
/// validator set at some height; no membership check happens here.
pub(crate) fn register_bls_key(
    action: &ChainAction,
    validator: &Address,
    pubkey: &[u8],
    current_height: u64,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    if !is_authorized(&action.sender, validator, operator_lookup)? {
        anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
    }
    let bytes = validated_bls_pubkey(pubkey)?;
    if let Some(owner) = bls_pubkey_owner_lookup(&BlsPublicKey(bytes))? {
        if &owner != validator {
            anyhow::bail!("BLS pubkey already registered to {owner}");
        }
    }
    Ok(BlockUpdates {
        // Effective one block later, same delay as `ValidatorSetSnapshot` —
        // see `BlsKeyRegistration`'s doc comment.
        bls_key: Some(BlsKeyRegistration {
            address: validator.clone(),
            pubkey: xc_bls::BlsPublicKey(bytes),
            effective_height: current_height + 1,
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
        view.put(&StakeByValidatorKey(&equivocator), &vec![equivocator.clone()])
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
            &|_, _| Ok::<bool, StorageError>(false),
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
    fn equivocation_evidence_rejected_when_already_processed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let equivocator = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let block_a = signed_chain_block(&key, 5, 100);
        let block_b = signed_chain_block(&key, 5, 200);

        let db = temp_db();
        let view = seeded_view(&db, HashMap::new(), HashMap::new());
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
            &|_, _| Ok::<bool, StorageError>(true),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already processed"));
    }

    #[test]
    fn register_bls_key_accepts_a_valid_pubkey() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (_, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(ACTION_FEE))]), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
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
        let (_, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(ACTION_FEE))]), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
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
            &|_, _| Ok::<bool, StorageError>(false),
            &owned_by_bob,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_bls_key_allows_re_registering_your_own_already_held_pubkey() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (_, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(ACTION_FEE))]), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                validator: alice.clone(),
                pubkey: pubkey.0.to_vec(),
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
            &|_, _| Ok::<bool, StorageError>(false),
            &owned_by_self,
        )
        .expect("re-registering your own key should stay a no-op success");
        assert_eq!(updates.bls_key.expect("expected a bls_key update").address, alice);
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
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid BLS public key"));
    }
}
