// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_circuit::{AdminKey, AdminRole, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Address, ClaimTopic};
use xc_storage::StorageError;

use crate::ChainAction;

/// Authorization check for the privileged roles — `action.sender` must be
/// the genesis-seeded holder of `role` (`AdminKey`, see
/// `Snapshot.{attestor,freeze,recovery}_admin`). One address per role on
/// chain; M-of-N approval is the custody behind that key, not a protocol
/// feature. Stays in the runtime: which address holds a role is chain
/// configuration, not identity logic.
pub(crate) fn require_admin<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    role: AdminRole,
) -> anyhow::Result<()> {
    let admin = view
        .get(&AdminKey(role))?
        .ok_or_else(|| anyhow::anyhow!("chain has no {} configured", role.name()))?;
    if action.sender != admin {
        anyhow::bail!("{} is not the {}", action.sender, role.name());
    }
    Ok(())
}

/// `AdminRole::Attestor`-gated. The registry itself lives in `circuit-identity`.
pub(crate) fn register_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    attestor: &Address,
    name: &str,
    reason: &str,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    crate::asset::check_reason(reason, "registering an attestor")?;
    require_admin(view, action, AdminRole::Attestor)?;
    Ok(BlockUpdates {
        attestor_registration: Some(circuit_identity::apply_register_attestor(
            view,
            attestor,
            name,
            current_height,
        )?),
        ..Default::default()
    })
}

pub(crate) fn deregister_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    attestor: &Address,
    reason: &str,
) -> anyhow::Result<BlockUpdates> {
    crate::asset::check_reason(reason, "deregistering an attestor")?;
    require_admin(view, action, AdminRole::Attestor)?;
    Ok(BlockUpdates {
        attestor_deregistration: Some(circuit_identity::apply_deregister_attestor(view, attestor)?),
        ..Default::default()
    })
}

pub(crate) fn grant_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    subject: &Address,
    hash: &str,
    topics: &[ClaimTopic],
    jurisdiction: Option<&str>,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    Ok(BlockUpdates {
        accounts: circuit_identity::apply_grant_attestation(
            view,
            &action.sender,
            subject,
            hash,
            topics,
            jurisdiction,
            current_height,
        )?,
        ..Default::default()
    })
}

pub(crate) fn revoke_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    subject: &Address,
) -> anyhow::Result<BlockUpdates> {
    Ok(BlockUpdates {
        accounts: circuit_identity::apply_revoke_attestation(view, &action.sender, subject)?,
        ..Default::default()
    })
}

/// The proof is bound to `action.sender` inside the circuit, so a replayed
/// proof fails verification instead of re-verifying whoever replays it.
pub(crate) fn verify_identity_credential<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    proof: &[u8],
) -> anyhow::Result<BlockUpdates> {
    Ok(BlockUpdates {
        accounts: circuit_identity::apply_verify_credential(view, &action.sender, proof)?,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use crate::ActionPayload;
    use crate::test_support::*;
    use ark_bls12_381::Bls12_381;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use std::collections::HashMap;
    use xc_circuit::AttestorRecordKey;
    use xc_primitives::{Action, Address, AttestorRecord};

    #[test]
    fn grant_attestation_then_verify_identity_credential_succeeds_end_to_end() {
        use ark_std::rand::{SeedableRng, rngs::StdRng};

        let attestor = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk =
            circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();
        let hash_hex = hex::encode(&hash_bytes);

        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (alice.clone(), funded(FEE_BUDGET * 2)),
                (attestor.clone(), funded(FEE_BUDGET)),
            ]),
            HashMap::new(),
        );
        view.put(
            &AttestorRecordKey(&attestor),
            &AttestorRecord {
                name: "test".to_string(),
                registered_at: 0,
            },
        )
        .unwrap();

        let grant = Action {
            sender: attestor.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::GrantAttestation {
                subject: alice.clone(),
                hash: hash_hex,
                topics: Vec::new(),
                jurisdiction: None,
            },
        };
        let grant_updates = crate::dispatch(
            &grant,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
        )
        .unwrap();
        assert!(grant_updates.accounts.0[&alice].identity_hash.is_some());
        view.apply_accounts(&grant_updates.accounts).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &[1u8; 32], &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let verify = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
        };
        let verify_updates = crate::dispatch(
            &verify,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
        )
        .unwrap();
        assert!(verify_updates.accounts.0[&alice].zk_identity_verified);
    }

    #[test]
    fn verify_identity_credential_accepts_a_valid_proof() {
        use ark_std::rand::{SeedableRng, rngs::StdRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk =
            circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &[1u8; 32], &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut account = funded(FEE_BUDGET);
        account.identity_hash = Some(hex::encode(hash_bytes));
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), account)]),
            HashMap::new(),
        );

        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
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
        assert!(
            updates
                .accounts
                .0
                .get(&alice)
                .expect("sender account must be updated")
                .zk_identity_verified
        );
    }

    /// The replay case: Bob is attested to the same hash as Alice and
    /// resubmits the proof Alice published. The runtime binds the proof to
    /// `action.sender`, so it fails for him.
    #[test]
    fn verify_identity_credential_rejects_a_proof_replayed_by_another_account() {
        use ark_std::rand::{SeedableRng, rngs::StdRng};

        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk =
            circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();

        // Alice's proof, bound to her key.
        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &[1u8; 32], &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut account = funded(FEE_BUDGET);
        account.identity_hash = Some(hex::encode(hash_bytes));
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(bob.clone(), account)]), HashMap::new());

        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
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
            err.to_string().contains("failed verification"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_identity_credential_rejects_malformed_proof_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let mut account = funded(FEE_BUDGET);
        account.identity_hash = Some(hex::encode([0u8; 32]));
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), account)]),
            HashMap::new(),
        );

        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential {
                proof: vec![0xFFu8; 4],
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
        assert!(err.to_string().contains("malformed zk proof bytes"));
    }

    #[test]
    fn verify_identity_credential_rejects_a_proof_for_the_wrong_hash() {
        use ark_std::rand::{SeedableRng, rngs::StdRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk =
            circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &[1u8; 32], &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        // Account's stored identity_hash doesn't match the preimage proven above.
        let params = circuit_identity_zk::poseidon_params();
        let wrong_hash = circuit_identity_zk::credential_hash(&params, b"a different preimage");
        let mut wrong_hash_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&wrong_hash, &mut wrong_hash_bytes)
            .unwrap();

        let mut account = funded(0);
        account.identity_hash = Some(hex::encode(wrong_hash_bytes));
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), account)]),
            HashMap::new(),
        );

        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
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
        assert!(err.to_string().contains("failed verification"));
    }
}
