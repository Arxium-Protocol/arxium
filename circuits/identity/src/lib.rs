// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The identity circuit: the attestor registry, attestations (the Trust
//! Spectrum's KYC marker on an account), and the zk credential proof that
//! upgrades an attestation to `zk_identity_verified`.
//!
//! Same shape as every circuit: plain arguments, read-only view, typed
//! errors, returns updates without writing them. The runtime decides *who*
//! may register an attestor (`AdminRole::Attestor`, a chain-config concern);
//! this crate decides what an attestor may do once registered.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use thiserror::Error;
use xc_circuit::{AccountKey, AttestorRecordKey, KvRead};
use xc_primitives::{Address, AttestorRecord, ClaimTopic};
use xc_storage::{AccountUpdates, AttestorDeregistration, AttestorRegistration, StorageError};

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("{0} is not a registered attestor")]
    NotAttestor(Address),
    #[error("{0} is already a registered attestor")]
    AlreadyAttestor(Address),
    #[error("jurisdiction {0:?} is not a 2-letter uppercase ISO-3166-1 alpha-2 code")]
    InvalidJurisdiction(String),
    #[error("account {0} not found")]
    AccountNotFound(Address),
    #[error("account has no identity_hash to prove")]
    NoIdentityHash,
    #[error("identity_hash is not a valid field element")]
    MalformedIdentityHash,
    #[error("malformed zk proof bytes")]
    MalformedProof,
    #[error("sender address is not a valid public key")]
    MalformedSender,
    #[error("zk credential proof failed verification")]
    ProofRejected,
}

/// ISO-3166-1 alpha-2, uppercase. Shared by attestation grants and asset
/// jurisdiction allowlists so the two sides can never disagree on format.
pub fn validate_jurisdiction_code(code: &str) -> Result<(), IdentityError> {
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(IdentityError::InvalidJurisdiction(code.to_string()));
    }
    Ok(())
}

/// `who` must be a currently-registered attestor. This is the Trust
/// Spectrum's multi-attestor model: more than one regulated KYC provider
/// can hold this authority at once.
pub fn require_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    who: &Address,
) -> Result<(), IdentityError> {
    if view.get(&AttestorRecordKey(who))?.is_none() {
        return Err(IdentityError::NotAttestor(who.clone()));
    }
    Ok(())
}

/// Whether `address` holds a live attestation: an `identity_hash` granted by
/// an attestor that is *still* in the registry. An attestation from a
/// since-deregistered attestor is exactly the case the registry exists to
/// revoke. Age is not checked here — that's per-asset
/// (`Asset.max_attestation_age`), the validator admission gate has no limit.
pub fn is_attested<V: KvRead<Error = StorageError>>(
    view: &V,
    address: &Address,
) -> Result<bool, StorageError> {
    let Some(entry) = view.get(&AccountKey(address))? else {
        return Ok(false);
    };
    if entry.identity_hash.is_none() {
        return Ok(false);
    }
    match &entry.attested_by {
        Some(attestor) => Ok(view.get(&AttestorRecordKey(attestor))?.is_some()),
        // Attested before the registry recorded who did it: the only
        // evidence is the hash itself. Accept.
        None => Ok(true),
    }
}

/// Rejected if already registered — deregister first to change `name`.
pub fn apply_register_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    name: &str,
    current_height: u64,
) -> Result<AttestorRegistration, IdentityError> {
    if view.get(&AttestorRecordKey(attestor))?.is_some() {
        return Err(IdentityError::AlreadyAttestor(attestor.clone()));
    }
    Ok(AttestorRegistration {
        attestor: attestor.clone(),
        record: AttestorRecord {
            name: name.to_string(),
            registered_at: current_height,
        },
    })
}

/// Attestations it already granted are untouched — `is_attested` stops
/// honouring them the moment the record is gone.
pub fn apply_deregister_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
) -> Result<AttestorDeregistration, IdentityError> {
    require_attestor(view, attestor)?;
    Ok(AttestorDeregistration(attestor.clone()))
}

/// Marks `subject` eligible by setting `AccountEntry.identity_hash`, and
/// records `attestor` and `current_height` — the accountability trail and
/// the clock `Asset.max_attestation_age` runs against. Creates a fresh
/// account entry if `subject` has none yet.
///
/// `topics` and `jurisdiction` replace the account's existing ones outright
/// rather than merging: an attestation is a statement of what an attestor
/// currently vouches for, so re-granting with a narrower topic list has to
/// be able to take a claim away.
pub fn apply_grant_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    subject: &Address,
    hash: &str,
    topics: &[ClaimTopic],
    jurisdiction: Option<&str>,
    current_height: u64,
) -> Result<AccountUpdates, IdentityError> {
    require_attestor(view, attestor)?;
    if let Some(code) = jurisdiction {
        validate_jurisdiction_code(code)?;
    }
    let mut entry = view.get(&AccountKey(subject))?.unwrap_or_default();
    entry.identity_hash = Some(hash.to_string());
    entry.attested_by = Some(attestor.clone());
    entry.attested_at = Some(current_height);
    // Deduped so repeated topics can't grow the list without bound across
    // re-grants; order is not meaningful to any reader.
    entry.claims = {
        let mut topics = topics.to_vec();
        topics.dedup();
        topics
    };
    entry.jurisdiction = jurisdiction.map(str::to_string);
    Ok(AccountUpdates(BTreeMap::from([(subject.clone(), entry)])))
}

/// Reverses `apply_grant_attestation` — clears every attestation-derived
/// field. A stale ZK-verified flag or a surviving `Accredited` claim would
/// keep gating decisions passing on an attestation that no longer exists.
pub fn apply_revoke_attestation<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    subject: &Address,
) -> Result<AccountUpdates, IdentityError> {
    require_attestor(view, attestor)?;
    let mut entry = view
        .get(&AccountKey(subject))?
        .ok_or_else(|| IdentityError::AccountNotFound(subject.clone()))?;
    entry.identity_hash = None;
    entry.zk_identity_verified = false;
    entry.attested_at = None;
    entry.claims.clear();
    entry.jurisdiction = None;
    Ok(AccountUpdates(BTreeMap::from([(subject.clone(), entry)])))
}

pub fn identity_zk_vk() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(circuit_identity_zk::VK_BYTES)
            .expect("checked-in devnet identity-zk verifying key is well-formed")
    })
}

/// Groth16 proof of knowledge of the preimage hashing to `sender`'s existing
/// `AccountEntry.identity_hash`. On success, marks `zk_identity_verified`.
///
/// The proof's second public input is derived here from `sender`, not read
/// from the proof, so a proof lifted from another account's on-chain
/// submission fails verification instead of re-verifying whoever replays it.
pub fn apply_verify_credential<V: KvRead<Error = StorageError>>(
    view: &V,
    sender: &Address,
    proof: &[u8],
) -> Result<AccountUpdates, IdentityError> {
    let mut entry = view
        .get(&AccountKey(sender))?
        .ok_or_else(|| IdentityError::AccountNotFound(sender.clone()))?;
    let hash_hex = entry
        .identity_hash
        .clone()
        .ok_or(IdentityError::NoIdentityHash)?;
    let hash_bytes = hex::decode(&hash_hex).map_err(|_| IdentityError::MalformedIdentityHash)?;
    let credential_hash = Fr::deserialize_compressed(hash_bytes.as_slice())
        .map_err(|_| IdentityError::MalformedIdentityHash)?;
    let parsed_proof = circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(proof)
        .map_err(|_| IdentityError::MalformedProof)?;
    let sender_pubkey = sender
        .pubkey_bytes()
        .map_err(|_| IdentityError::MalformedSender)?;
    let binding = circuit_identity_zk::sender_binding(&sender_pubkey);
    if !circuit_identity_zk::verify(&credential_hash, &binding, &parsed_proof, identity_zk_vk()) {
        return Err(IdentityError::ProofRejected);
    }
    entry.zk_identity_verified = true;
    Ok(AccountUpdates(BTreeMap::from([(sender.clone(), entry)])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_storage::ArxiumDb;

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    fn db_with_attestor(attestor: &Address) -> ArxiumDb {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("arxium-test-identity-{nanos}"));
        let db = ArxiumDb::open(&path).unwrap();
        db.write_batch(&apply_register_attestor(&db, attestor, "test", 0).unwrap())
            .unwrap();
        db
    }

    #[test]
    fn granting_replaces_topics_and_revoking_clears_them() {
        let attestor = addr(9);
        let alice = addr(1);
        let db = db_with_attestor(&attestor);

        let updates = apply_grant_attestation(
            &db,
            &attestor,
            &alice,
            "kyc-alice",
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            Some("CH"),
            7,
        )
        .unwrap();
        let entry = &updates.0[&alice];
        assert_eq!(entry.claims, vec![ClaimTopic::Kyc, ClaimTopic::Accredited]);
        assert_eq!(entry.jurisdiction.as_deref(), Some("CH"));
        assert_eq!(entry.attested_by.as_ref(), Some(&attestor));
        assert_eq!(entry.attested_at, Some(7));
        db.write_batch(&updates).unwrap();
        assert!(is_attested(&db, &alice).unwrap());

        let updates = apply_grant_attestation(
            &db,
            &attestor,
            &alice,
            "kyc-alice",
            &[ClaimTopic::Kyc],
            Some("DE"),
            8,
        )
        .unwrap();
        let entry = &updates.0[&alice];
        assert_eq!(
            entry.claims,
            vec![ClaimTopic::Kyc],
            "re-grant replaces, never merges"
        );
        assert_eq!(entry.jurisdiction.as_deref(), Some("DE"));
        db.write_batch(&updates).unwrap();

        let updates = apply_revoke_attestation(&db, &attestor, &alice).unwrap();
        let entry = &updates.0[&alice];
        assert!(entry.identity_hash.is_none());
        assert!(entry.attested_at.is_none());
        assert!(
            entry.claims.is_empty(),
            "a revoked attestation must leave no claims standing"
        );
        assert!(entry.jurisdiction.is_none());
        db.write_batch(&updates).unwrap();
        assert!(!is_attested(&db, &alice).unwrap());
    }

    #[test]
    fn only_registered_attestors_may_grant_and_deregistration_voids_their_grants() {
        let attestor = addr(9);
        let alice = addr(1);
        let db = db_with_attestor(&attestor);
        assert!(matches!(
            apply_grant_attestation(&db, &addr(8), &alice, "h", &[], None, 0).unwrap_err(),
            IdentityError::NotAttestor(_)
        ));
        let grant = apply_grant_attestation(&db, &attestor, &alice, "h", &[], None, 0).unwrap();
        db.write_batch(&grant).unwrap();
        assert!(is_attested(&db, &alice).unwrap());

        let dereg = apply_deregister_attestor(&db, &attestor).unwrap();
        db.write_batch(&dereg).unwrap();
        assert!(!is_attested(&db, &alice).unwrap());
    }

    #[test]
    fn grant_rejects_a_malformed_jurisdiction_code() {
        let attestor = addr(9);
        let alice = addr(1);
        let db = db_with_attestor(&attestor);
        for bad in ["ch", "CHE", "C", "C1"] {
            assert!(
                matches!(
                    apply_grant_attestation(&db, &attestor, &alice, "h", &[], Some(bad), 0)
                        .unwrap_err(),
                    IdentityError::InvalidJurisdiction(_)
                ),
                "code {bad:?}"
            );
        }
        assert!(apply_grant_attestation(&db, &attestor, &alice, "h", &[], Some("CH"), 0).is_ok());
        assert!(apply_grant_attestation(&db, &attestor, &alice, "h", &[], None, 0).is_ok());
    }

    #[test]
    fn verify_credential_accepts_own_proof_and_rejects_a_replay() {
        use ark_serialize::CanonicalSerialize;
        use ark_std::rand::{SeedableRng, rngs::StdRng};

        let attestor = addr(9);
        let alice = addr(1);
        let bob = addr(2);
        let db = db_with_attestor(&attestor);
        let pk_bytes: &[u8] = include_bytes!("../../identity-zk/pk.bin");
        let pk =
            circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();
        let preimage = b"alice's secret preimage";
        let hash =
            circuit_identity_zk::credential_hash(&circuit_identity_zk::poseidon_params(), preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();
        let hash_hex = hex::encode(&hash_bytes);
        for who in [&alice, &bob] {
            let g = apply_grant_attestation(&db, &attestor, who, &hash_hex, &[], None, 0).unwrap();
            db.write_batch(&g).unwrap();
        }

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &[1u8; 32], &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let ok = apply_verify_credential(&db, &alice, &proof_bytes).unwrap();
        assert!(ok.0[&alice].zk_identity_verified);
        assert!(matches!(
            apply_verify_credential(&db, &bob, &proof_bytes).unwrap_err(),
            IdentityError::ProofRejected
        ));
        assert!(matches!(
            apply_verify_credential(&db, &alice, &[0xFF; 4]).unwrap_err(),
            IdentityError::MalformedProof
        ));
    }
}
