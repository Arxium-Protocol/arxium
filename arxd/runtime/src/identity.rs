// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use std::sync::OnceLock;
use xc_circuit::{AccountKey, KvRead};
use xc_executor::BlockUpdates;
use xc_storage::{AccountUpdates, BlockView};

use crate::ChainAction;

pub(crate) fn identity_zk_vk() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(circuit_identity_zk::VK_BYTES)
            .expect("checked-in devnet identity-zk verifying key is well-formed")
    })
}

/// Groth16 proof of knowledge of the preimage hashing (via
/// `circuit_identity_zk`'s Poseidon circuit) to sender's existing
/// `AccountEntry.identity_hash`. Verified against the checked-in devnet
/// verifying key — see `circuits/identity-zk`'s module docs for why the
/// key isn't from a real trusted-setup ceremony. On success, marks
/// `zk_identity_verified` on the sender's account.
pub(crate) fn verify_identity_credential(
    view: &BlockView<'_>,
    action: &ChainAction,
    proof: &[u8],
) -> anyhow::Result<BlockUpdates> {
    let entry = view
        .get(&AccountKey(&action.sender))?
        .ok_or_else(|| anyhow::anyhow!("account {} not found", action.sender))?;
    let hash_hex = entry
        .identity_hash
        .clone()
        .ok_or_else(|| anyhow::anyhow!("account has no identity_hash to prove"))?;
    let hash_bytes =
        hex::decode(&hash_hex).map_err(|_| anyhow::anyhow!("identity_hash is not valid hex"))?;
    let credential_hash = Fr::deserialize_compressed(hash_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("identity_hash is not a valid field element"))?;
    let parsed_proof = circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(proof)
        .map_err(|_| anyhow::anyhow!("malformed zk proof bytes"))?;
    if !circuit_identity_zk::verify(&credential_hash, &parsed_proof, identity_zk_vk()) {
        anyhow::bail!("zk credential proof failed verification");
    }
    let mut verified_entry = entry;
    verified_entry.zk_identity_verified = true;
    Ok(BlockUpdates {
        accounts: AccountUpdates(std::collections::BTreeMap::from([(
            action.sender.clone(),
            verified_entry,
        )])),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{ACTION_FEE, ActionPayload};
    use ark_serialize::CanonicalSerialize;
    use std::collections::HashMap;
    use xc_primitives::{Action, Address};
    use xc_storage::StorageError;

    #[test]
    fn verify_identity_credential_accepts_a_valid_proof() {
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut account = funded(ACTION_FEE);
        account.identity_hash = Some(hex::encode(hash_bytes));
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), account)]), HashMap::new());

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
            &|_, _| Ok::<bool, StorageError>(false),
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

    #[test]
    fn verify_identity_credential_rejects_malformed_proof_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let mut account = funded(ACTION_FEE);
        account.identity_hash = Some(hex::encode([0u8; 32]));
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), account)]), HashMap::new());

        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: vec![0xFFu8; 4] },
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
        assert!(err.to_string().contains("malformed zk proof bytes"));
    }

    #[test]
    fn verify_identity_credential_rejects_a_proof_for_the_wrong_hash() {
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        // Account's stored identity_hash doesn't match the preimage proven above.
        let params = circuit_identity_zk::poseidon_params();
        let wrong_hash = circuit_identity_zk::credential_hash(&params, b"a different preimage");
        let mut wrong_hash_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&wrong_hash, &mut wrong_hash_bytes).unwrap();

        let mut account = funded(0);
        account.identity_hash = Some(hex::encode(wrong_hash_bytes));
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), account)]), HashMap::new());

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
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed verification"));
    }
}
