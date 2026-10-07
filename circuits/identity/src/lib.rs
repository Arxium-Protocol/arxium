// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The identity circuit: the attestor registry, attestations (the Trust
//! Spectrum's KYC marker on an account), and the zk credential proof that
//! upgrades an attestation to `zk_identity_verified`.
//!
//! Same shape as every circuit: plain arguments, read-only view, typed
//! errors, returns updates without writing them. Attestors are added and
//! removed only by governance (`circuit-governance` calls the registry
//! functions here); this crate decides what an attestor may do once
//! registered, and what a registration must look like.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use thiserror::Error;
use xc_circuit::{AccountKey, AttestorNameKey, AttestorRecordKey, KvRead};
use xc_primitives::{
    Address, Asset, AttestorRecord, ClaimTopic, attestor_name_skeleton, validate_attestor_multisig,
    validate_attestor_name,
};
use xc_storage::{
    AccountUpdates, AttestorDeregistration, AttestorRegistration, GovernanceUpdates, StorageError,
};

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("{0} is not a registered attestor")]
    NotAttestor(Address),
    #[error("{0} is already a registered attestor")]
    AlreadyAttestor(Address),
    #[error("{0} is blocked from granting attestations")]
    AttestorBlocked(Address),
    #[error("invalid attestor name: {0}")]
    InvalidName(&'static str),
    #[error("attestor name {0:?} is too close to one already registered")]
    NameTaken(String),
    #[error("invalid attestor multisig: {0}")]
    InvalidMultisig(&'static str),
    #[error("{0} already has a removal vote open")]
    RemovalPending(Address),
    #[error(
        "{attestor} survived a removal vote and cannot be targeted again before height {until}"
    )]
    RemovalCooldown { attestor: Address, until: u64 },
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
    #[error("{0} has no live attestation")]
    NotAttested(Address),
    #[error("asset has no claims a proof could satisfy")]
    NothingToProve,
    #[error("asset's jurisdiction list is empty or has a code outside ISO 3166-1 alpha-2")]
    UnprovableJurisdictions,
    #[error("sub is not a valid field element")]
    MalformedSub,
    #[error("proof dated day {claimed}, but this block is on day {block_day}")]
    WrongDate { claimed: u32, block_day: u64 },
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
) -> Result<AttestorRecord, IdentityError> {
    view.get(&AttestorRecordKey(who))?
        .ok_or_else(|| IdentityError::NotAttestor(who.clone()))
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

/// Rejected if already registered, or if the name is invalid or too close to
/// a registered one (`attestor_name_skeleton`). Returns the record write and
/// the name row that guards its uniqueness.
pub fn apply_register_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    name: &str,
    owners: &[Address],
    threshold: u8,
    current_height: u64,
) -> Result<(AttestorRegistration, GovernanceUpdates), IdentityError> {
    validate_attestor_name(name).map_err(IdentityError::InvalidName)?;
    validate_attestor_multisig(attestor, owners, threshold)
        .map_err(IdentityError::InvalidMultisig)?;
    if view.get(&AttestorRecordKey(attestor))?.is_some() {
        return Err(IdentityError::AlreadyAttestor(attestor.clone()));
    }
    let skeleton = attestor_name_skeleton(name);
    if view.get(&AttestorNameKey(&skeleton))?.is_some() {
        return Err(IdentityError::NameTaken(name.to_string()));
    }
    let mut name_row = GovernanceUpdates::default();
    name_row.put(&AttestorNameKey(&skeleton), attestor)?;
    Ok((
        AttestorRegistration {
            attestor: attestor.clone(),
            record: AttestorRecord {
                name: name.to_string(),
                registered_at: current_height,
                owners: owners.to_vec(),
                threshold,
                ..Default::default()
            },
        },
        name_row,
    ))
}

/// Attestations it already granted are untouched — `is_attested` stops
/// honouring them the moment the record is gone. Frees the name.
pub fn apply_deregister_attestor<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
) -> Result<(AttestorDeregistration, GovernanceUpdates), IdentityError> {
    let record = require_attestor(view, attestor)?;
    let mut name_row = GovernanceUpdates::default();
    name_row.delete(&AttestorNameKey(&attestor_name_skeleton(&record.name)));
    Ok((AttestorDeregistration(attestor.clone()), name_row))
}

/// Sets or clears the attestor's own emergency block. The runtime lets only
/// the attestor set it (`BlockAttestor`) and only a vote clear it
/// (`UnblockAttestor`); this function is just the write.
pub fn apply_set_self_blocked<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    blocked: bool,
) -> Result<GovernanceUpdates, IdentityError> {
    let mut record = require_attestor(view, attestor)?;
    record.self_blocked = blocked;
    let mut updates = GovernanceUpdates::default();
    updates.put(&AttestorRecordKey(attestor), &record)?;
    Ok(updates)
}

/// A removal vote is opening: the attestor cannot grant until it closes.
/// One at a time per attestor, and not again right after a failed vote.
pub fn apply_open_removal<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    current_height: u64,
) -> Result<GovernanceUpdates, IdentityError> {
    let mut record = require_attestor(view, attestor)?;
    if record.removal_pending {
        return Err(IdentityError::RemovalPending(attestor.clone()));
    }
    if current_height < record.removal_cooldown_until {
        return Err(IdentityError::RemovalCooldown {
            attestor: attestor.clone(),
            until: record.removal_cooldown_until,
        });
    }
    record.removal_pending = true;
    let mut updates = GovernanceUpdates::default();
    updates.put(&AttestorRecordKey(attestor), &record)?;
    Ok(updates)
}

/// A removal vote that did not pass (rejected, or its attestor is already
/// gone): lifts the block and starts the cooldown. The caller handles a vote
/// that passed with `apply_deregister_attestor`.
pub fn apply_close_failed_removal<V: KvRead<Error = StorageError>>(
    view: &V,
    attestor: &Address,
    current_height: u64,
    cooldown_blocks: u64,
) -> Result<GovernanceUpdates, IdentityError> {
    let mut updates = GovernanceUpdates::default();
    if let Some(mut record) = view.get(&AttestorRecordKey(attestor))? {
        record.removal_pending = false;
        record.removal_cooldown_until = current_height.saturating_add(cooldown_blocks);
        updates.put(&AttestorRecordKey(attestor), &record)?;
    }
    Ok(updates)
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
    // Only new grants are blocked. Revoking, and everything already granted,
    // is untouched, so a block cannot be used to wipe or strand KYC.
    if require_attestor(view, attestor)?.blocked() {
        return Err(IdentityError::AttestorBlocked(attestor.clone()));
    }
    if let Some(code) = jurisdiction {
        validate_jurisdiction_code(code)?;
    }
    let mut entry = view.get(&AccountKey(subject))?.unwrap_or_default();
    // `zk_identity_verified` vouches for a proof over the *old* hash; a new
    // credential has to be proven again, same reason revocation clears it.
    if entry.identity_hash.as_deref() != Some(hash) {
        entry.zk_identity_verified = false;
    }
    entry.identity_hash = Some(hash.to_string());
    entry.attested_by = Some(attestor.clone());
    entry.attested_at = Some(current_height);
    // Deduped so repeated topics can't grow the list without bound across
    // re-grants; order is not meaningful to any reader. Not `Vec::dedup`,
    // which only drops *adjacent* repeats (`[Kyc, Aml, Kyc]` kept both).
    entry.claims = {
        let mut unique: Vec<ClaimTopic> = Vec::with_capacity(topics.len());
        for topic in topics {
            if !unique.contains(topic) {
                unique.push(topic.clone());
            }
        }
        unique
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

fn predicate_vk() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(
            circuit_identity_zk::PREDICATE_VK_BYTES,
        )
        .expect("checked-in devnet predicate verifying key is well-formed")
    })
}

/// zk-KYC (whitepaper §8.2): `sender`'s attested credential leaf opens to
/// claims that satisfy `asset`'s `required_claims` and `allowed_jurisdictions`,
/// without the claims or the country appearing anywhere on chain.
///
/// Same `PredicateCircuit` as Arx ID sign-in, with every public input but
/// `sub` and `today_days` rebuilt here from state, never from the payload:
/// - `today_days` (what credential expiry is checked against) must be within
///   a day of `block_timestamp`'s calendar day, so a proof made just before
///   midnight still lands, but a backdated one can't revive an expired
///   credential.
/// - `merkle_root` is the root of a one-leaf tree holding `sender`'s own
///   `identity_hash`, so the proof speaks for this account's credential
///   and can't be made with someone else's (no credential lending).
/// - `scope` is the asset, `nonce` the sender's key: a proof for another
///   asset, or replayed by another sender, fails verification.
/// - `claims_mask` and the country set come from the asset record.
pub fn verify_claim_proof<V: KvRead<Error = StorageError>>(
    view: &V,
    sender: &Address,
    asset: &Asset,
    sub: &[u8; 32],
    today_days: u32,
    block_timestamp: u64,
    proof: &[u8],
) -> Result<(), IdentityError> {
    let block_day =
        block_timestamp / 86_400 + u64::from(circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS);
    if u64::from(today_days).abs_diff(block_day) > 1 {
        return Err(IdentityError::WrongDate {
            claimed: today_days,
            block_day,
        });
    }
    use circuit_identity_zk::predicate::{self, ACCREDITED, AML, KYC, RESIDENCY};

    if !is_attested(view, sender)? {
        return Err(IdentityError::NotAttested(sender.clone()));
    }
    let entry = view
        .get(&AccountKey(sender))?
        .ok_or_else(|| IdentityError::AccountNotFound(sender.clone()))?;
    let hash_hex = entry.identity_hash.ok_or(IdentityError::NoIdentityHash)?;
    let leaf = hex::decode(&hash_hex)
        .ok()
        .and_then(|bytes| Fr::deserialize_compressed(bytes.as_slice()).ok())
        .ok_or(IdentityError::MalformedIdentityHash)?;

    // `Jurisdiction` needs no bit of its own: every v1 leaf carries a
    // country, and `allowed_jurisdictions` below is what restricts it.
    let mut mask = asset.required_claims.iter().fold(0, |mask, topic| {
        mask | match topic {
            ClaimTopic::Kyc => KYC,
            ClaimTopic::Aml => AML,
            ClaimTopic::Accredited => ACCREDITED,
            ClaimTopic::Jurisdiction => 0,
        }
    });
    let countries = match &asset.allowed_jurisdictions {
        Some(allowed) => {
            mask |= RESIDENCY;
            predicate::country_set(allowed.iter().map(String::as_str))
                .ok_or(IdentityError::UnprovableJurisdictions)?
        }
        None => Vec::new(),
    };
    // A zero mask skips the leaf check inside the circuit entirely.
    if mask == 0 {
        return Err(IdentityError::NothingToProve);
    }

    let sender_pubkey = sender
        .pubkey_bytes()
        .map_err(|_| IdentityError::MalformedSender)?;
    let public = predicate::asset_claim_public(
        &circuit_identity_zk::poseidon_params(),
        leaf,
        &sender_pubkey,
        &asset.asset_ref.to_string(),
        mask,
        &countries,
        Fr::deserialize_compressed(sub.as_slice()).map_err(|_| IdentityError::MalformedSub)?,
        today_days,
    );
    let proof = circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(proof)
        .map_err(|_| IdentityError::MalformedProof)?;
    if !predicate::verify_predicate(public, &proof, predicate_vk()) {
        return Err(IdentityError::ProofRejected);
    }
    Ok(())
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
        // Counter, not just nanos: parallel test threads can read the same
        // clock value and land on one RocksDB path (see `open_test_db` in
        // `arxd/finality`).
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "arxium-test-identity-{}-{nanos}-{n}",
            std::process::id()
        ));
        let db = ArxiumDb::open(&path).unwrap();
        // Seeded directly: the multisig rule is exercised on its own below.
        db.write_batch(&AttestorRegistration {
            attestor: attestor.clone(),
            record: AttestorRecord {
                name: "test".into(),
                ..Default::default()
            },
        })
        .unwrap();
        db
    }

    /// A 2-of-3 attestor address and its owners, distinct per `seed`.
    fn multisig(seed: u8) -> (Address, Vec<Address>) {
        let owners: Vec<Address> = (0..3).map(|i| addr(seed + i)).collect();
        let members: Vec<[u8; 32]> = (0..3).map(|i| [seed + i; 32]).collect();
        (
            xc_primitives::multisig_address(2, &members).unwrap(),
            owners,
        )
    }

    fn register(db: &ArxiumDb, seed: u8, name: &str) -> Result<Address, IdentityError> {
        let (attestor, owners) = multisig(seed);
        let (registration, name_row) = apply_register_attestor(db, &attestor, name, &owners, 2, 5)?;
        db.write_batch(&registration).unwrap();
        db.write_batch(&name_row).unwrap();
        Ok(attestor)
    }

    #[test]
    fn registration_needs_a_multisig_a_clean_name_and_a_free_skeleton() {
        let db = db_with_attestor(&addr(99));
        let (attestor, owners) = multisig(10);
        let try_register = |attestor: &Address, name: &str, owners: &[Address], t| {
            apply_register_attestor(&db, attestor, name, owners, t, 5).map(|_| ())
        };
        assert!(matches!(
            try_register(&attestor, "Bank", &owners, 1),
            Err(IdentityError::InvalidMultisig(_))
        ));
        assert!(matches!(
            try_register(&addr(10), "Bank", &owners, 2),
            Err(IdentityError::InvalidMultisig(_))
        ));
        assert!(matches!(
            try_register(&attestor, "B", &owners, 2),
            Err(IdentityError::InvalidName(_))
        ));
        register(&db, 10, "Arxium Bank").unwrap();
        let record = KvRead::get(&db, &AttestorRecordKey(&attestor))
            .unwrap()
            .unwrap();
        assert_eq!((record.threshold, record.owners.len()), (2, 3));
        // A lookalike name is refused; the same attestor twice is refused.
        assert!(matches!(
            register(&db, 20, "ARX1UM bank"),
            Err(IdentityError::NameTaken(_))
        ));
        assert!(matches!(
            register(&db, 10, "Other Name"),
            Err(IdentityError::AlreadyAttestor(_))
        ));
        // Removing it frees the name.
        let (dereg, name_row) = apply_deregister_attestor(&db, &attestor).unwrap();
        db.write_batch(&dereg).unwrap();
        db.write_batch(&name_row).unwrap();
        register(&db, 20, "ARX1UM bank").unwrap();
    }

    #[test]
    fn a_blocked_attestor_cannot_grant_but_can_still_revoke_and_what_it_granted_stays() {
        let (attestor, alice, bob) = (addr(9), addr(1), addr(2));
        let db = db_with_attestor(&attestor);
        db.write_batch(
            &apply_grant_attestation(&db, &attestor, &alice, "h", &[], None, 1).unwrap(),
        )
        .unwrap();
        for block in [
            // The attestor's own emergency block.
            apply_set_self_blocked(&db, &attestor, true).unwrap(),
            // An open removal vote.
            apply_open_removal(&db, &attestor, 2).unwrap(),
        ] {
            db.write_batch(&block).unwrap();
        }
        assert!(matches!(
            apply_grant_attestation(&db, &attestor, &bob, "h", &[], None, 3).unwrap_err(),
            IdentityError::AttestorBlocked(_)
        ));
        assert!(is_attested(&db, &alice).unwrap());
        apply_revoke_attestation(&db, &attestor, &alice).unwrap();
        // Unblocking the self-block alone is not enough: the removal vote is open.
        db.write_batch(&apply_set_self_blocked(&db, &attestor, false).unwrap())
            .unwrap();
        assert!(apply_grant_attestation(&db, &attestor, &bob, "h", &[], None, 3).is_err());
        db.write_batch(&apply_close_failed_removal(&db, &attestor, 10, 100).unwrap())
            .unwrap();
        apply_grant_attestation(&db, &attestor, &bob, "h", &[], None, 11).unwrap();
    }

    #[test]
    fn one_removal_vote_at_a_time_and_a_cooldown_after_a_failed_one() {
        let attestor = addr(9);
        let db = db_with_attestor(&attestor);
        db.write_batch(&apply_open_removal(&db, &attestor, 1).unwrap())
            .unwrap();
        assert!(matches!(
            apply_open_removal(&db, &attestor, 2).unwrap_err(),
            IdentityError::RemovalPending(_)
        ));
        db.write_batch(&apply_close_failed_removal(&db, &attestor, 5, 100).unwrap())
            .unwrap();
        assert!(matches!(
            apply_open_removal(&db, &attestor, 104).unwrap_err(),
            IdentityError::RemovalCooldown { until: 105, .. }
        ));
        apply_open_removal(&db, &attestor, 105).unwrap();
    }

    #[test]
    fn grant_dedupes_non_adjacent_repeated_topics() {
        let attestor = addr(1);
        let db = db_with_attestor(&attestor);
        let updates = apply_grant_attestation(
            &db,
            &attestor,
            &addr(2),
            "ab",
            &[ClaimTopic::Kyc, ClaimTopic::Aml, ClaimTopic::Kyc],
            None,
            1,
        )
        .unwrap();
        assert_eq!(
            updates.0[&addr(2)].claims,
            vec![ClaimTopic::Kyc, ClaimTopic::Aml]
        );
    }

    /// A zk-verified flag earned for one credential must not carry over to a
    /// different one granted later.
    #[test]
    fn a_new_identity_hash_clears_zk_identity_verified() {
        let attestor = addr(1);
        let db = db_with_attestor(&attestor);
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            addr(2),
            xc_primitives::AccountEntry {
                identity_hash: Some("aa".into()),
                zk_identity_verified: true,
                ..Default::default()
            },
        )])))
        .unwrap();
        let same = apply_grant_attestation(&db, &attestor, &addr(2), "aa", &[], None, 1).unwrap();
        assert!(same.0[&addr(2)].zk_identity_verified, "same hash keeps it");
        let new = apply_grant_attestation(&db, &attestor, &addr(2), "bb", &[], None, 1).unwrap();
        assert!(!new.0[&addr(2)].zk_identity_verified);
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

        let (dereg, _) = apply_deregister_attestor(&db, &attestor).unwrap();
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

    mod claim_proof {
        use super::*;
        use ark_serialize::CanonicalSerialize;
        use ark_std::rand::{SeedableRng, rngs::StdRng};
        use circuit_identity_zk::predicate::{self, KYC, RESIDENCY};
        use circuit_identity_zk::{CredentialOpening, ProvingKey};

        const TODAY: u32 = 46_290;
        /// A block timestamp on `TODAY`.
        const NOW: u64 =
            (TODAY - circuit_identity_zk::CREDENTIAL_EPOCH_OFFSET_DAYS) as u64 * 86_400;

        fn pk() -> &'static ProvingKey<Bls12_381> {
            static PK: OnceLock<ProvingKey<Bls12_381>> = OnceLock::new();
            PK.get_or_init(|| {
                ProvingKey::deserialize_compressed_unchecked(
                    include_bytes!("../../identity-zk/predicate_pk.bin").as_slice(),
                )
                .unwrap()
            })
        }

        struct Holder {
            secret: Fr,
            opening: CredentialOpening,
        }

        impl Holder {
            fn new(secret: u64, country: &[u8; 2]) -> Self {
                Self {
                    secret: Fr::from(secret),
                    opening: CredentialOpening {
                        kyc: true,
                        aml: false,
                        accredited: false,
                        birth_date_days: 30_000,
                        country_code: *country,
                        membership_root: Fr::from(0u64),
                        expiry_days: 50_000,
                        salt: Fr::from(secret + 1000),
                    },
                }
            }

            fn leaf(&self) -> Fr {
                let params = circuit_identity_zk::poseidon_params();
                let commitment = circuit_identity_zk::id_commitment(&params, self.secret);
                circuit_identity_zk::credential_leaf(&params, commitment, &self.opening)
            }

            fn leaf_hex(&self) -> String {
                let mut bytes = Vec::new();
                self.leaf().serialize_compressed(&mut bytes).unwrap();
                hex::encode(bytes)
            }

            /// What an honest wallet does, but with every public input the
            /// prover's own choice — the chain must rebuild them, not trust
            /// them. Always a satisfiable statement, so a rejection proves
            /// the chain's inputs differ, not that proving failed.
            fn prove(
                &self,
                prover: &Address,
                asset: &Asset,
                mask: u32,
                countries: &[&str],
            ) -> ([u8; 32], Vec<u8>) {
                let (sub, proof) = predicate::prove_asset_claim(
                    self.secret,
                    &self.opening,
                    &prover.pubkey_bytes().unwrap(),
                    &asset.asset_ref.to_string(),
                    mask,
                    &predicate::country_set(countries.iter().copied()).unwrap_or_default(),
                    TODAY,
                    pk(),
                    &mut StdRng::seed_from_u64(3),
                )
                .unwrap();
                let (mut sub_bytes, mut proof_bytes) = (Vec::new(), Vec::new());
                sub.serialize_compressed(&mut sub_bytes).unwrap();
                proof.serialize_compressed(&mut proof_bytes).unwrap();
                (sub_bytes.try_into().unwrap(), proof_bytes)
            }
        }

        /// EEA + Switzerland: 31 countries, well past the old ten-slot limit.
        const EEA_AND_CH: [&str; 31] = [
            "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR",
            "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO",
            "SE", "SI", "SK",
        ];

        /// KYC required, EEA or Swiss holders only.
        fn bond(name: &str) -> Asset {
            let mut asset = Asset::new(name, addr(7), false);
            asset.required_claims = vec![ClaimTopic::Kyc];
            asset.allowed_jurisdictions = Some(EEA_AND_CH.map(String::from).to_vec());
            asset
        }

        fn grant(db: &ArxiumDb, attestor: &Address, who: &Address, holder: &Holder) {
            db.write_batch(
                &apply_grant_attestation(db, attestor, who, &holder.leaf_hex(), &[], None, 1)
                    .unwrap(),
            )
            .unwrap();
        }

        #[test]
        fn a_holder_proves_claims_and_jurisdiction_without_either_on_chain() {
            let (attestor, alice) = (addr(9), addr(1));
            let db = db_with_attestor(&attestor);
            let holder = Holder::new(11, b"CH");
            grant(&db, &attestor, &alice, &holder);
            let entry = KvRead::get(&db, &AccountKey(&alice)).unwrap().unwrap();
            assert!(entry.claims.is_empty() && entry.jurisdiction.is_none());

            let asset = bond("bond");
            let (sub, proof) = holder.prove(&alice, &asset, KYC | RESIDENCY, &EEA_AND_CH);
            verify_claim_proof(&db, &alice, &asset, &sub, TODAY, NOW, &proof).unwrap();
        }

        #[test]
        fn proofs_of_a_weaker_statement_or_for_someone_else_are_rejected() {
            let (attestor, alice, bob) = (addr(9), addr(1), addr(2));
            let db = db_with_attestor(&attestor);
            let alice_cred = Holder::new(11, b"CH");
            grant(&db, &attestor, &alice, &alice_cred);
            let bob_cred = Holder::new(22, b"US");
            grant(&db, &attestor, &bob, &bob_cred);
            let asset = bond("bond");
            let rejected = |who: &Address, (sub, proof): ([u8; 32], Vec<u8>)| {
                matches!(
                    verify_claim_proof(&db, who, &asset, &sub, TODAY, NOW, &proof),
                    Err(IdentityError::ProofRejected)
                )
            };

            // Wrong jurisdiction: Bob (US) proves residency in a set he's in.
            assert!(rejected(
                &bob,
                bob_cred.prove(&bob, &asset, KYC | RESIDENCY, &["US"])
            ));
            // Wrong claim: a proof that skips the asset's KYC requirement.
            let mut no_kyc = Holder::new(33, b"CH");
            no_kyc.opening.kyc = false;
            grant(&db, &attestor, &bob, &no_kyc);
            assert!(rejected(
                &bob,
                no_kyc.prove(&bob, &asset, RESIDENCY, &EEA_AND_CH)
            ));
            // Wrong root: Bob submits a proof over Alice's credential.
            assert!(rejected(
                &bob,
                alice_cred.prove(&bob, &asset, KYC | RESIDENCY, &EEA_AND_CH)
            ));
            // Replay: Alice's own proof, submitted by Bob.
            let alices = alice_cred.prove(&alice, &asset, KYC | RESIDENCY, &EEA_AND_CH);
            assert!(rejected(&bob, alices.clone()));
            // Wrong asset: Alice's proof for `bond` against another asset.
            let other = bond("other");
            assert!(matches!(
                verify_claim_proof(&db, &alice, &other, &alices.0, TODAY, NOW, &alices.1),
                Err(IdentityError::ProofRejected)
            ));
            verify_claim_proof(&db, &alice, &asset, &alices.0, TODAY, NOW, &alices.1)
                .expect("the untampered proof still verifies");
        }

        /// Expiry is checked against the block's calendar day, with a day of
        /// slack either side; anything further is refused before verifying.
        #[test]
        fn a_proof_dated_more_than_a_day_from_the_block_is_refused() {
            let db = db_with_attestor(&addr(9));
            let asset = bond("bond");
            for (claimed, ok) in [
                (TODAY - 2, false),
                (TODAY - 1, true),
                (TODAY + 1, true),
                (TODAY + 2, false),
            ] {
                let result =
                    verify_claim_proof(&db, &addr(1), &asset, &[0; 32], claimed, NOW + 3_600, &[]);
                assert_eq!(
                    !matches!(result, Err(IdentityError::WrongDate { .. })),
                    ok,
                    "day {claimed}: {result:?}"
                );
            }
        }

        #[test]
        fn unattested_senders_and_unprovable_assets_are_refused_before_verifying() {
            let (attestor, alice) = (addr(9), addr(1));
            let db = db_with_attestor(&attestor);
            let asset = bond("bond");
            assert!(matches!(
                verify_claim_proof(&db, &alice, &asset, &[0; 32], TODAY, NOW, &[]),
                Err(IdentityError::NotAttested(_))
            ));
            grant(&db, &attestor, &alice, &Holder::new(11, b"CH"));

            let mut open = asset.clone();
            open.required_claims.clear();
            open.allowed_jurisdictions = None;
            assert!(matches!(
                verify_claim_proof(&db, &alice, &open, &[0; 32], TODAY, NOW, &[]),
                Err(IdentityError::NothingToProve)
            ));
            // Any number of countries is provable (the old ten-slot limit is
            // gone): an 11-country list gets as far as parsing the proof.
            let mut wide = asset.clone();
            wide.allowed_jurisdictions = Some(
                [
                    "AT", "BE", "CH", "DE", "DK", "ES", "FI", "FR", "IE", "IT", "NL",
                ]
                .map(String::from)
                .to_vec(),
            );
            assert!(matches!(
                verify_claim_proof(&db, &alice, &wide, &[0; 32], TODAY, NOW, &[]),
                Err(IdentityError::MalformedSub | IdentityError::MalformedProof)
            ));
            // A code outside ISO 3166-1 has no leaf in the country tree.
            let mut unknown = asset;
            unknown.allowed_jurisdictions = Some(vec!["CH".into(), "XX".into()]);
            assert!(matches!(
                verify_claim_proof(&db, &alice, &unknown, &[0; 32], TODAY, NOW, &[]),
                Err(IdentityError::UnprovableJurisdictions)
            ));
        }
    }
}
