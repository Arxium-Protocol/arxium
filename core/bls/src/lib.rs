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
const DST: &[u8] = b"ARXIUM_FINALITY_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

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
/// signer's contribution, so this is aggregate signature (not aggregate
/// message) verification.
pub fn verify_aggregate(msg: &[u8], signers: &[BlsPublicKey], agg: &BlsSignature) -> Result<(), BlsError> {
    if signers.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let pks: Vec<PublicKey> = signers
        .iter()
        .map(|p| PublicKey::from_bytes(&p.0).map_err(|_| BlsError::InvalidPublicKey))
        .collect::<Result<_, _>>()?;
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let signature = Signature::from_bytes(&agg.0).map_err(|_| BlsError::InvalidSignature)?;
    let msgs: Vec<&[u8]> = pk_refs.iter().map(|_| msg).collect();
    map_blst_err(signature.aggregate_verify(true, &msgs, DST, &pk_refs, true))
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
}
