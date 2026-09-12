// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use std::sync::OnceLock;
use xc_circuit::{AccountKey, AttestorRecordKey, GovernorKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{AccountEntry, Address, AttestorRecord, ClaimTopic};
use xc_storage::{AccountUpdates, AttestorDeregistration, AttestorRegistration, StorageError};

use crate::ChainAction;

/// Shared authorization check for `GrantAttestation`/`RevokeAttestation` —
/// both require `action.sender` to be a currently-registered attestor
/// (`CF_ATTESTORS`, membership managed by `register_attestor`/
/// `deregister_attestor`, both `GovernorKey`-gated). This is the Trust
/// Spectrum's multi-attestor model: more than one regulated KYC provider
/// can hold this authority at once, rather than one chain-spec-fixed
/// address for the whole chain's lifetime.
fn require_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
) -> anyhow::Result<()> {
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
pub(crate) fn require_governor<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
) -> anyhow::Result<()> {
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
            record: AttestorRecord {
                name: name.to_string(),
                registered_at: current_height,
            },
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
///
/// `topics` and `jurisdiction` replace the account's existing ones outright
/// rather than merging into them. An attestation is a statement of what an
/// attestor currently vouches for, so re-granting with a narrower topic list
/// has to be able to take a claim away — merging would make claims
/// append-only and leave `RevokeAttestation` as the only way to drop one,
/// which also clears the subject's `identity_hash` as collateral damage.
pub(crate) fn grant_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    subject: &Address,
    hash: &str,
    topics: &[ClaimTopic],
    jurisdiction: Option<&str>,
) -> anyhow::Result<BlockUpdates> {
    require_attestor(view, action)?;
    if let Some(code) = jurisdiction
        && (code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()))
    {
        anyhow::bail!("jurisdiction {code:?} is not a 2-letter uppercase ISO-3166-1 alpha-2 code");
    }
    let mut entry = view.get(&AccountKey(subject))?.unwrap_or(AccountEntry {
        balance: 0,
        ..Default::default()
    });
    entry.identity_hash = Some(hash.to_string());
    entry.attested_by = Some(action.sender.clone());
    // Deduped so repeated topics can't grow the list without bound across
    // re-grants; order is not meaningful to any reader.
    entry.claims = {
        let mut topics = topics.to_vec();
        topics.dedup();
        topics
    };
    entry.jurisdiction = jurisdiction.map(str::to_string);
    Ok(BlockUpdates {
        accounts: AccountUpdates(std::collections::BTreeMap::from([(subject.clone(), entry)])),
        ..Default::default()
    })
}

/// Reverses `grant_attestation` — clears `identity_hash`,
/// `zk_identity_verified`, `claims` and `jurisdiction`. A revoked attestation
/// must not leave any of them standing: a stale ZK-verified flag or a
/// surviving `Accredited` claim would keep gating decisions passing on an
/// attestation that no longer exists.
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
    entry.claims.clear();
    entry.jurisdiction = None;
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

    /// Re-granting replaces the topic set rather than merging into it, and
    /// revoking clears every attestation-derived field. Both matter for
    /// gating: a merge would make claims append-only, and a partial revoke
    /// would leave a stale claim satisfying an asset's `required_claims`.
    #[test]
    fn granting_replaces_topics_and_revoking_clears_them() {
        use xc_primitives::ClaimTopic;

        let attestor = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(attestor.clone(), funded(ACTION_FEE * 4))]),
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

        let action = ChainAction {
            sender: attestor.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RevokeAttestation {
                subject: alice.clone(),
            },
        };

        let updates = grant_attestation(
            &view,
            &action,
            &alice,
            "kyc-alice",
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            Some("CH"),
        )
        .unwrap();
        let entry = &updates.accounts.0[&alice];
        assert_eq!(entry.claims, vec![ClaimTopic::Kyc, ClaimTopic::Accredited]);
        assert_eq!(entry.jurisdiction.as_deref(), Some("CH"));
        assert_eq!(entry.attested_by.as_ref(), Some(&attestor));
        view.apply_accounts(&updates.accounts).unwrap();

        // Narrower re-grant: Accredited is dropped, not kept.
        let updates = grant_attestation(
            &view,
            &action,
            &alice,
            "kyc-alice",
            &[ClaimTopic::Kyc],
            Some("DE"),
        )
        .unwrap();
        let entry = &updates.accounts.0[&alice];
        assert_eq!(
            entry.claims,
            vec![ClaimTopic::Kyc],
            "re-grant replaces, never merges"
        );
        assert_eq!(entry.jurisdiction.as_deref(), Some("DE"));
        view.apply_accounts(&updates.accounts).unwrap();

        let updates = revoke_attestation(&view, &action, &alice).unwrap();
        let entry = &updates.accounts.0[&alice];
        assert!(entry.identity_hash.is_none());
        assert!(
            entry.claims.is_empty(),
            "a revoked attestation must leave no claims standing"
        );
        assert!(entry.jurisdiction.is_none());
    }

    #[test]
    fn grant_rejects_a_malformed_jurisdiction_code() {
        let attestor = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(attestor.clone(), funded(ACTION_FEE))]),
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
        let action = ChainAction {
            sender: attestor,
            nonce: 0,
            signature: None,
            payload: ActionPayload::RevokeAttestation {
                subject: alice.clone(),
            },
        };

        for bad in ["ch", "CHE", "C", "C1"] {
            let err = grant_attestation(&view, &action, &alice, "h", &[], Some(bad)).unwrap_err();
            assert!(
                err.to_string().contains("jurisdiction"),
                "code {bad:?}, got: {err}"
            );
        }
        assert!(grant_attestation(&view, &action, &alice, "h", &[], Some("CH")).is_ok());
        assert!(grant_attestation(&view, &action, &alice, "h", &[], None).is_ok());
    }

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
                (alice.clone(), funded(ACTION_FEE * 2)),
                (attestor.clone(), funded(ACTION_FEE)),
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
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut account = funded(ACTION_FEE);
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

    #[test]
    fn verify_identity_credential_rejects_malformed_proof_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let mut account = funded(ACTION_FEE);
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
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
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
