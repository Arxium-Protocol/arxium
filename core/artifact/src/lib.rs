// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Evidence artifact format: a self-describing, JSON-encoded proof of a
//! consensus fault, plus a `verify()` function that checks it without
//! decoding any chain-specific payload.
//!
//! Deliberately depends on nothing chain-shaped (no `xc-primitives`, no
//! storage, no node code) and encodes as JSON, not bincode: an artifact may
//! be read by a stranger, possibly years from now, possibly not in Rust. It
//! must stand on its own.
//!
//! Each block a fault cites contributes a `CanonicalHeader` + `signature`.
//! `verify()` recomputes the signing bytes from the header itself — it does
//! not trust a supplied blob of "what was signed", because opaque bytes
//! can't be checked for the property that actually matters here: that the
//! two headers are truly at the same height and truly distinct. Decoded
//! blocks are also included under `human_readable`, non-normative, for a
//! person to see what was equivocated; `verify()` never reads that field.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Frozen once shipped: an artifact written today must still verify in ten
/// years, so this never changes meaning, only grows new `Fault` variants.
pub const ARTIFACT_VERSION: u32 = 1;

/// The fields a proposer's signature actually covers (mirrors
/// `xc_primitives::block::BlockSigningPayload` byte-for-byte, so
/// `verify()` recomputes the exact same signing bytes without needing to
/// depend on `xc-primitives` or know the chain-specific action payload
/// type `P`). Chain-agnostic by construction: nothing here requires
/// decoding `actions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalHeader {
    pub height: u64,
    pub parent_hash: String,
    pub timestamp: u64,
    /// Hex-encoded (`0x...`) Merkle root over the block's actions.
    pub tx_root: String,
    /// Bech32 address of the proposer (matches `xc_primitives::Address`'s
    /// wire encoding exactly — see `signing_bytes` below).
    pub proposer: String,
    pub state_root: String,
}

/// What `BlockSigningPayload` actually encodes, reimplemented here so the
/// bincode bytes match `xc_primitives::block::Block::signing_bytes` without
/// this crate depending on `xc-primitives`.
#[derive(Serialize)]
struct SigningPayload<'a> {
    height: u64,
    parent_hash: &'a str,
    timestamp: u64,
    tx_root: &'a [u8; 32],
    proposer: &'a str,
    state_root: &'a str,
}

fn signing_bytes(header: &CanonicalHeader) -> Result<Vec<u8>, VerifyError> {
    let tx_root = decode_hex("tx_root", &header.tx_root)?;
    let tx_root: [u8; 32] =
        tx_root.as_slice().try_into().map_err(|_| VerifyError::BadTxRootLength(tx_root.len()))?;
    let payload = SigningPayload {
        height: header.height,
        parent_hash: &header.parent_hash,
        timestamp: header.timestamp,
        tx_root: &tx_root,
        proposer: &header.proposer,
        state_root: &header.state_root,
    };
    let config = bincode::config::standard();
    Ok(bincode::serde::encode_to_vec(&payload, config).expect("payload encoding never fails"))
}

/// One block's contribution to a fault: enough to recompute the signing
/// bytes and check the signature, nothing requires decoding `P`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAttestation {
    pub header: CanonicalHeader,
    /// Hex-encoded (`0x...`) Ed25519 signature over the header's
    /// recomputed signing bytes.
    pub signature: String,
}

/// One variant today, because equivocation is the only fault this codebase
/// can currently produce — deliberately not a generic multi-fault
/// framework. Tagged so more fault types have an obvious place to land
/// later without breaking this one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum Fault {
    Equivocation {
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the culpable proposer.
        proposer_pubkey: String,
        height: u64,
        blocks: [BlockAttestation; 2],
    },
}

/// A complete, standalone evidence artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub artifact_version: u32,
    /// Binds the artifact to one chain, so evidence from one network can't
    /// be presented as evidence against another.
    pub genesis_hash: String,
    #[serde(flatten)]
    pub fault: Fault,
    /// Decoded blocks, for a person to see what was equivocated.
    /// Non-normative: `verify()` never reads this field.
    pub human_readable: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("unsupported artifact_version {0}, verifier knows version {ARTIFACT_VERSION}")]
    UnsupportedVersion(u32),
    #[error("{field} not valid hex: {source}")]
    BadHex { field: &'static str, #[source] source: hex::FromHexError },
    #[error("tx_root must be 32 bytes, got {0}")]
    BadTxRootLength(usize),
    #[error("proposer_pubkey must be 32 bytes, got {0}")]
    BadPubkeyLength(usize),
    #[error("proposer_pubkey does not decode to a valid Ed25519 public key")]
    BadPubkey,
    #[error("signature must be 64 bytes, got {0}")]
    BadSignatureLength(usize),
    #[error("the two cited headers are at different heights ({0} vs {1}), not equivocation")]
    HeightMismatch(u64, u64),
    #[error("fault claims height {claimed} but the cited headers are at height {actual}")]
    FaultHeightMismatch { claimed: u64, actual: u64 },
    #[error("the two cited headers sign identical bytes, not distinct evidence")]
    SameBlock,
    #[error("signature over block {0} does not verify against proposer_pubkey")]
    SignatureInvalid(usize),
}

/// What a verified artifact proves, once `verify()` accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub fault: &'static str,
    /// Hex-encoded (`0x...`) raw Ed25519 public key of the culpable party.
    pub culpable_pubkey: String,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, VerifyError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|source| VerifyError::BadHex { field, source })
}

/// Verifies an [`EvidenceArtifact`] without decoding any chain-specific
/// action payload. Recomputes each header's signing bytes independently —
/// it does not trust anything the artifact merely asserts about what was
/// signed, since an attacker who controls the artifact controls that
/// assertion too.
pub fn verify(artifact: &EvidenceArtifact) -> Result<Verdict, VerifyError> {
    if artifact.artifact_version != ARTIFACT_VERSION {
        return Err(VerifyError::UnsupportedVersion(artifact.artifact_version));
    }

    match &artifact.fault {
        Fault::Equivocation { proposer_pubkey, height, blocks } => {
            let pubkey_bytes = decode_hex("proposer_pubkey", proposer_pubkey)?;
            let pubkey_bytes: [u8; 32] = pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadPubkeyLength(pubkey_bytes.len()))?;
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadPubkey)?;

            if blocks[0].header.height != blocks[1].header.height {
                return Err(VerifyError::HeightMismatch(
                    blocks[0].header.height,
                    blocks[1].header.height,
                ));
            }
            if blocks[0].header.height != *height {
                return Err(VerifyError::FaultHeightMismatch {
                    claimed: *height,
                    actual: blocks[0].header.height,
                });
            }

            let mut signed = Vec::with_capacity(2);
            for (i, block) in blocks.iter().enumerate() {
                let bytes = signing_bytes(&block.header)?;
                let sig_bytes = decode_hex("signature", &block.signature)?;
                let sig_bytes: [u8; 64] = sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| VerifyError::BadSignatureLength(sig_bytes.len()))?;
                let signature = Signature::from_bytes(&sig_bytes);
                verifying_key
                    .verify(&bytes, &signature)
                    .map_err(|_| VerifyError::SignatureInvalid(i))?;
                signed.push(bytes);
            }

            if signed[0] == signed[1] {
                return Err(VerifyError::SameBlock);
            }

            Ok(Verdict { fault: "equivocation", culpable_pubkey: proposer_pubkey.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn header(height: u64, tx_root: u8, proposer: &str) -> CanonicalHeader {
        CanonicalHeader {
            height,
            parent_hash: "0xparent".to_string(),
            timestamp: 1234,
            tx_root: format!("0x{}", hex::encode([tx_root; 32])),
            proposer: proposer.to_string(),
            state_root: "0xstate".to_string(),
        }
    }

    fn attestation(key: &SigningKey, header: CanonicalHeader) -> BlockAttestation {
        let bytes = signing_bytes(&header).unwrap();
        let signature = key.sign(&bytes);
        BlockAttestation { header, signature: format!("0x{}", hex::encode(signature.to_bytes())) }
    }

    fn artifact(key: &SigningKey, blocks: [BlockAttestation; 2], height: u64) -> EvidenceArtifact {
        let pubkey = format!("0x{}", hex::encode(key.verifying_key().as_bytes()));
        EvidenceArtifact {
            artifact_version: ARTIFACT_VERSION,
            genesis_hash: "0xgenesis".to_string(),
            fault: Fault::Equivocation { proposer_pubkey: pubkey, height, blocks },
            human_readable: serde_json::json!({}),
        }
    }

    #[test]
    fn valid_equivocation_verifies() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(5, 2, "arx1proposer"));
        let verdict = verify(&artifact(&key, [a, b], 5)).unwrap();
        assert_eq!(verdict.fault, "equivocation");
    }

    #[test]
    fn json_round_trips() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(5, 2, "arx1proposer"));
        let art = artifact(&key, [a, b], 5);
        let json = serde_json::to_string_pretty(&art).unwrap();
        let parsed: EvidenceArtifact = serde_json::from_str(&json).unwrap();
        verify(&parsed).unwrap();
    }

    #[test]
    fn wrong_signature_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&other, header(5, 2, "arx1proposer"));
        assert!(matches!(
            verify(&artifact(&key, [a, b], 5)),
            Err(VerifyError::SignatureInvalid(1))
        ));
    }

    /// Flaw 1 from review: same block duplicated into both evidence slots
    /// with only a cosmetic difference (here: nothing at all — identical
    /// header, identical signature) must not verify as equivocation. Since
    /// `block_hash` no longer exists in the normative struct, an attacker
    /// can't even construct the old attack; this just confirms two
    /// identical headers are rejected as the same block.
    #[test]
    fn identical_headers_are_rejected_as_same_block() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(5, 1, "arx1proposer"));
        assert!(matches!(verify(&artifact(&key, [a, b], 5)), Err(VerifyError::SameBlock)));
    }

    /// Flaw 2 from review (fatal): any two blocks ever signed by the same
    /// validator, at any two heights, must not verify as equivocation for
    /// either height.
    #[test]
    fn different_heights_are_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(6, 2, "arx1proposer"));
        assert!(matches!(
            verify(&artifact(&key, [a, b], 5)),
            Err(VerifyError::HeightMismatch(5, 6))
        ));
    }

    #[test]
    fn fault_height_must_match_headers() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(5, 2, "arx1proposer"));
        // Claimed height (99) disagrees with what the headers actually say (5).
        assert!(matches!(
            verify(&artifact(&key, [a, b], 99)),
            Err(VerifyError::FaultHeightMismatch { claimed: 99, actual: 5 })
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let a = attestation(&key, header(5, 1, "arx1proposer"));
        let b = attestation(&key, header(5, 2, "arx1proposer"));
        let mut art = artifact(&key, [a, b], 5);
        art.artifact_version = 2;
        assert!(matches!(verify(&art), Err(VerifyError::UnsupportedVersion(2))));
    }
}
