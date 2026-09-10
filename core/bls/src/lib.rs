// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! BLS12-381 signatures (min-pk scheme: 48-byte pubkeys in G1, 96-byte
//! signatures in G2) for block finality certificates. Role-agnostic crypto
//! primitive — no consensus/quorum logic lives here, that's `arxd/finality`.

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use serde::{Deserialize, Serialize};

/// Domain separation tag — required by the BLS signature spec so a
/// signature can't be replayed as valid under a different scheme/curve use.
///
/// This is the IRTF *proof-of-possession* scheme's tag (`..._POP_`), not the
/// basic scheme's. [`verify_aggregate`] aggregates N signatures over one
/// identical message, which is `FastAggregateVerify` — only sound when every
/// key has proven possession of its secret (see [`prove_possession`]).
/// Signing under the PoP tag is what makes the scheme label honest, and keeps
/// a signature from ever verifying under a basic-scheme implementation that
/// doesn't require PoP.
const DST: &[u8] = b"ARXIUM_FINALITY_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Separate tag for proofs of possession, per the spec: a PoP must not be
/// reusable as an ordinary signature (or vice versa), which is exactly what
/// a shared tag would allow — a validator could be tricked into signing a
/// message that happens to be another validator's pubkey bytes.
const POP_DST: &[u8] = b"ARXIUM_FINALITY_BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    #[error("invalid BLS secret key seed")]
    InvalidSecretKey,
    #[error("invalid BLS public key bytes")]
    InvalidPublicKey,
    #[error("invalid BLS signature bytes")]
    InvalidSignature,
    #[error("cannot aggregate an empty signature set")]
    EmptyAggregate,
    #[error("signature verification failed")]
    VerificationFailed,
}

fn map_blst_err(err: BLST_ERROR) -> Result<(), BlsError> {
    if err == BLST_ERROR::BLST_SUCCESS { Ok(()) } else { Err(BlsError::VerificationFailed) }
}

#[derive(Clone)]
pub struct BlsSecretKey(SecretKey);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPublicKey(#[serde(with = "serde_bytes_48")] pub [u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature(#[serde(with = "serde_bytes_96")] pub [u8; 96]);

mod serde_bytes_48 {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| D::Error::custom("expected 48 bytes"))
    }
}

mod serde_bytes_96 {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 96], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| D::Error::custom("expected 96 bytes"))
    }
}

/// Deterministic from a 32-byte seed, same shape as `ed25519_dalek::SigningKey::from_bytes`.
pub fn keygen_from_seed(seed: &[u8; 32]) -> Result<(BlsSecretKey, BlsPublicKey), BlsError> {
    let sk = SecretKey::key_gen(seed, &[]).map_err(|_| BlsError::InvalidSecretKey)?;
    let pk = sk.sk_to_pk();
    Ok((BlsSecretKey(sk), BlsPublicKey(pk.to_bytes())))
}

pub fn sign(sk: &BlsSecretKey, msg: &[u8]) -> BlsSignature {
    BlsSignature(sk.0.sign(msg, DST, &[]).to_bytes())
}

/// Proof of possession: a signature over the public key's own bytes, under a
/// tag used for nothing else. Mandatory before a key may be registered
/// anywhere it will later be aggregated over — see [`verify_possession`].
pub fn prove_possession(sk: &BlsSecretKey) -> BlsSignature {
    BlsSignature(sk.0.sign(&sk.0.sk_to_pk().to_bytes(), POP_DST, &[]).to_bytes())
}

/// Verifies a [`prove_possession`] proof, and that `pubkey` is a valid
/// non-infinity group element.
///
/// **This is a consensus-safety requirement, not a formality.**
/// [`verify_aggregate`] checks N signatures over one identical message, where
/// the pairing product collapses to `e(sig, g2) == e(H(m), ∏ pk_i)` — it
/// verifies the *product* of the keys, not each key. Without a PoP, an
/// attacker who registers a rogue key `pk_r = g^x · (∏ honest pk_i)^-1`
/// (a perfectly valid group element, so subgroup checks don't catch it) can
/// produce `sig = H(m)^x` alone and have it verify against the whole honest
/// set — forging a quorum certificate for any message, signed by validators
/// who never voted. Requiring a signature under `pk_r` proves the attacker
/// knows its discrete log, which it cannot for a key built that way.
pub fn verify_possession(pubkey: &BlsPublicKey, pop: &BlsSignature) -> Result<(), BlsError> {
    let pk = PublicKey::from_bytes(&pubkey.0).map_err(|_| BlsError::InvalidPublicKey)?;
    pk.validate().map_err(|_| BlsError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&pop.0).map_err(|_| BlsError::InvalidSignature)?;
    map_blst_err(signature.verify(true, &pubkey.0, POP_DST, &[], &pk, true))
}

pub fn verify(msg: &[u8], pubkey: &BlsPublicKey, sig: &BlsSignature) -> Result<(), BlsError> {
    let pk = PublicKey::from_bytes(&pubkey.0).map_err(|_| BlsError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&sig.0).map_err(|_| BlsError::InvalidSignature)?;
    map_blst_err(signature.verify(true, msg, DST, &[], &pk, true))
}

/// Aggregates N signatures into one. Callers must separately verify each
/// signer is who they claim (e.g. via `verify_aggregate`) — aggregation
/// itself proves nothing about who signed.
pub fn aggregate(sigs: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
    if sigs.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let parsed: Vec<Signature> = sigs
        .iter()
        .map(|s| Signature::from_bytes(&s.0).map_err(|_| BlsError::InvalidSignature))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&Signature> = parsed.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true).map_err(|_| BlsError::VerificationFailed)?;
    Ok(BlsSignature(agg.to_signature().to_bytes()))
}

/// Verifies one aggregate signature was produced by all of `signers` over
/// the same `msg` — the finality-certificate check. All signers vouching
/// for the identical block hash means the same message is used for every
/// signer's contribution, so this is `FastAggregateVerify`.
///
/// **Caller contract:** every key in `signers` must have had its
/// [`verify_possession`] proof checked at registration, and `signers` must
/// contain no duplicates. This is `FastAggregateVerify`, which is only sound
/// under those two conditions — see [`verify_possession`] for what an
/// unproven key buys an attacker. On this chain the registration side is
/// `arxd/runtime`'s `validated_bls_pubkey` and the genesis BLS-key writer;
/// the duplicate check is in the certificate verifiers that call this.
///
/// (This used to call blst's `aggregate_verify` with the message repeated N
/// times. That implements `CoreAggregateVerify`, which is documented as
/// sound only for *distinct* messages; with identical ones it degenerates
/// into exactly this check while merely looking like the stricter one.)
pub fn verify_aggregate(msg: &[u8], signers: &[BlsPublicKey], agg: &BlsSignature) -> Result<(), BlsError> {
    if signers.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let pks: Vec<PublicKey> = signers
        .iter()
        .map(|p| {
            let pk = PublicKey::from_bytes(&p.0).map_err(|_| BlsError::InvalidPublicKey)?;
            // `fast_aggregate_verify` has no `pks_validate` flag of its own,
            // unlike the `aggregate_verify` this replaced — keep the check.
            pk.validate().map_err(|_| BlsError::InvalidPublicKey)?;
            Ok(pk)
        })
        .collect::<Result<_, BlsError>>()?;
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let signature = Signature::from_bytes(&agg.0).map_err(|_| BlsError::InvalidSignature)?;
    map_blst_err(signature.fast_aggregate_verify(true, msg, DST, &pk_refs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, pk) = keygen_from_seed(&[7u8; 32]).unwrap();
        let sig = sign(&sk, b"block-hash-abc");
        assert!(verify(b"block-hash-abc", &pk, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, pk) = keygen_from_seed(&[7u8; 32]).unwrap();
        let sig = sign(&sk, b"block-hash-abc");
        assert!(verify(b"different-hash", &pk, &sig).is_err());
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let (sk_a, _) = keygen_from_seed(&[1u8; 32]).unwrap();
        let (_, pk_b) = keygen_from_seed(&[2u8; 32]).unwrap();
        let sig = sign(&sk_a, b"block-hash-abc");
        assert!(verify(b"block-hash-abc", &pk_b, &sig).is_err());
    }

    #[test]
    fn aggregate_and_verify_quorum() {
        let keys: Vec<_> = (0u8..5).map(|i| keygen_from_seed(&[i + 10; 32]).unwrap()).collect();
        let msg = b"finalized-block-hash";
        let sigs: Vec<BlsSignature> = keys.iter().map(|(sk, _)| sign(sk, msg)).collect();
        let pubkeys: Vec<BlsPublicKey> = keys.iter().map(|(_, pk)| *pk).collect();

        let agg = aggregate(&sigs).unwrap();
        assert!(verify_aggregate(msg, &pubkeys, &agg).is_ok());
    }

    #[test]
    fn aggregate_verify_rejects_missing_signer() {
        let keys: Vec<_> = (0u8..3).map(|i| keygen_from_seed(&[i + 20; 32]).unwrap()).collect();
        let msg = b"finalized-block-hash";
        let sigs: Vec<BlsSignature> = keys.iter().map(|(sk, _)| sign(sk, msg)).collect();
        let agg = aggregate(&sigs).unwrap();

        // Claim a fourth signer that never actually signed.
        let (_, extra_pk) = keygen_from_seed(&[99u8; 32]).unwrap();
        let mut pubkeys: Vec<BlsPublicKey> = keys.iter().map(|(_, pk)| *pk).collect();
        pubkeys.push(extra_pk);

        assert!(verify_aggregate(msg, &pubkeys, &agg).is_err());
    }

    #[test]
    fn aggregate_rejects_empty_input() {
        assert!(aggregate(&[]).is_err());
    }

    #[test]
    fn proof_of_possession_roundtrip() {
        let (sk, pk) = keygen_from_seed(&[31u8; 32]).unwrap();
        assert!(verify_possession(&pk, &prove_possession(&sk)).is_ok());
    }

    /// The registration gate that closes the rogue-key attack. A rogue key
    /// `pk_r = g^x · (∏ honest pk_i)^-1` is a valid group element — it passes
    /// `PublicKey::validate()`, which is all registration used to check — but
    /// its owner cannot produce a signature under it, so it cannot produce a
    /// PoP either. Stand-in here for the same reason we don't hand-build the
    /// rogue point: any key whose secret the submitter doesn't hold fails,
    /// and the rogue key is exactly such a key.
    #[test]
    fn proof_of_possession_rejects_a_key_whose_secret_the_prover_lacks() {
        let (sk_a, _) = keygen_from_seed(&[32u8; 32]).unwrap();
        let (_, pk_b) = keygen_from_seed(&[33u8; 32]).unwrap();
        // A PoP over someone else's pubkey bytes, signed with our own key.
        let forged = BlsSignature(sk_a.0.sign(&pk_b.0, POP_DST, &[]).to_bytes());
        assert!(verify_possession(&pk_b, &forged).is_err());
        // And our own honest PoP doesn't transfer to their key either.
        assert!(verify_possession(&pk_b, &prove_possession(&sk_a)).is_err());
    }

    /// The two tags must not be interchangeable: if they were, a validator
    /// signing an attacker-chosen message that happened to be another
    /// validator's pubkey bytes would hand out a PoP for free.
    #[test]
    fn a_precommit_signature_is_not_a_valid_proof_of_possession() {
        let (sk, pk) = keygen_from_seed(&[34u8; 32]).unwrap();
        assert!(verify_possession(&pk, &sign(&sk, &pk.0)).is_err());
        assert!(verify(&pk.0, &pk, &prove_possession(&sk)).is_err());
    }
}
