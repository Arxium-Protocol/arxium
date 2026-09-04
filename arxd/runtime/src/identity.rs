// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use std::sync::OnceLock;
use xc_circuit::{AccountKey, AttestorRecordKey, GovernorKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{AccountEntry, Address, AttestorRecord};
use xc_storage::{AccountUpdates, AttestorDeregistration, AttestorRegistration, StorageError};

use crate::ChainAction;

/// Shared authorization check for `GrantAttestation`/`RevokeAttestation` —
/// both require `action.sender` to be a currently-registered attestor
/// (`CF_ATTESTORS`, membership managed by `register_attestor`/
/// `deregister_attestor`, both `GovernorKey`-gated). This is the Trust
/// Spectrum's multi-attestor model: more than one regulated KYC provider
/// can hold this authority at once, rather than one chain-spec-fixed
/// address for the whole chain's lifetime.
fn require_attestor<V: KvRead<Error = StorageError>>(view: &V, action: &ChainAction) -> anyhow::Result<()> {
    if view.get(&AttestorRecordKey(&action.sender))?.is_none() {
        anyhow::bail!("{} is not a registered attestor", action.sender);
    }
    Ok(())
}

/// Authorization check for `RegisterAttestor`/`DeregisterAttestor` —
/// `action.sender` must be the chain-spec-designated governor
/// (`identity::GovernorKey`, seeded at genesis; see `Snapshot.governor`).
/// Deliberately a single fixed address for now, same walking-skeleton
/// stage `require_attestor` used to be: a Compliance Committee
/// (multi-sig/voting) is the deferred upgrade for this role.
fn require_governor<V: KvRead<Error = StorageError>>(view: &V, action: &ChainAction) -> anyhow::Result<()> {
    let governor = view
        .get(&GovernorKey)?
        .ok_or_else(|| anyhow::anyhow!("chain has no governor configured"))?;
    if action.sender != governor {
        anyhow::bail!("{} is not the chain governor", action.sender);
    }
    Ok(())
}

/// Adds `attestor` to the trusted-attestor set. Rejected if already
/// registered — deregister first to change `name`.
pub(crate) fn register_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    attestor: &Address,
    name: &str,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    require_governor(view, action)?;
    if view.get(&AttestorRecordKey(attestor))?.is_some() {
        anyhow::bail!("{attestor} is already a registered attestor");
    }
    Ok(BlockUpdates {
        attestor_registration: Some(AttestorRegistration {
            attestor: attestor.clone(),
            record: AttestorRecord { name: name.to_string(), registered_at: current_height },
        }),
        ..Default::default()
    })
}

/// Removes `attestor` from the trusted-attestor set. Attestations it
/// already granted are untouched — see `require_attestor`'s doc comment on
/// who may revoke them.
pub(crate) fn deregister_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    attestor: &Address,
) -> anyhow::Result<BlockUpdates> {
    require_governor(view, action)?;
    if view.get(&AttestorRecordKey(attestor))?.is_none() {
        anyhow::bail!("{attestor} is not a registered attestor");
    }
    Ok(BlockUpdates {
        attestor_deregistration: Some(AttestorDeregistration(attestor.clone())),
        ..Default::default()
    })
}

/// Marks `subject` eligible by setting `AccountEntry.identity_hash`, and
/// records `action.sender` as the attestor who granted it — the minimum
/// accountability trail needed once more than one attestor can grant
/// attestations (no slashing or dispute path on top of it yet).
/// Creates a fresh account entry if `subject` has none yet.
pub(crate) fn grant_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    subject: &Address,
    hash: &str,
) -> anyhow::Result<BlockUpdates> {
    require_attestor(view, action)?;
    let mut entry = view.get(&AccountKey(subject))?.unwrap_or(AccountEntry {
        balance: 0,
        nonce: 0,
        identity_hash: None,
        zk_identity_verified: false,
        attested_by: None,
    });
    entry.identity_hash = Some(hash.to_string());
    entry.attested_by = Some(action.sender.clone());
    Ok(BlockUpdates {
        accounts: AccountUpdates(std::collections::BTreeMap::from([(subject.clone(), entry)])),
        ..Default::default()
    })
}

/// Reverses `grant_attestation` — clears `identity_hash` and
/// `zk_identity_verified` (a revoked KYC status shouldn't leave a stale
/// ZK-verified flag standing).
pub(crate) fn revoke_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    subject: &Address,
) -> anyhow::Result<BlockUpdates> {
    require_attestor(view, action)?;
    let mut entry = view
        .get(&AccountKey(subject))?
        .ok_or_else(|| anyhow::anyhow!("account {subject} not found"))?;
    entry.identity_hash = None;
    entry.zk_identity_verified = false;
    Ok(BlockUpdates {
        accounts: AccountUpdates(std::collections::BTreeMap::from([(subject.clone(), entry)])),
        ..Default::default()
    })
}

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
pub(crate) fn verify_identity_credential<V: KvRead<Error = StorageError>>(
    view: &V,
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
    fn grant_attestation_then_verify_identity_credential_succeeds_end_to_end() {
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let attestor = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();
        let hash_hex = hex::encode(&hash_bytes);

        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE * 2)), (attestor.clone(), funded(ACTION_FEE))]),
            HashMap::new(),
        );
        view.put(&AttestorRecordKey(&attestor), &AttestorRecord { name: "test".to_string(), registered_at: 0 }).unwrap();

        let grant = Action {
            sender: attestor.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::GrantAttestation { subject: alice.clone(), hash: hash_hex },
        };
        let grant_updates = crate::dispatch(
            &grant,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();
        assert!(grant_updates.accounts.0[&alice].identity_hash.is_some());
        view.apply_accounts(&grant_updates.accounts).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
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
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();
        assert!(verify_updates.accounts.0[&alice].zk_identity_verified);
    }

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
