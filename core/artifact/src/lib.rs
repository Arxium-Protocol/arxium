// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Evidence artifact format: a self-describing, JSON-encoded proof of a
//! consensus fault, plus a `verify()` that checks it without decoding any
//! chain-specific payload.
//!
//! Deliberately depends on nothing chain-shaped (no `xc-primitives`, no
//! storage, no node code) and encodes as JSON, not bincode: an artifact is
//! read by a stranger, possibly years from now, possibly not in Rust. It
//! must stand on its own.
//!
//! Each block a fault cites contributes `signing_bytes` + `signature` +
//! `block_hash` rather than a decoded block, so `verify()` is pure Ed25519
//! plus a hash comparison — the same verifier works for CoreChain and every
//! Spoke Chain's payload type, because it never needs to know what that type
//! is.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Frozen once shipped: an artifact written today must still verify in ten
/// years, so this never changes meaning, only grows new `Fault` variants.
pub const ARTIFACT_VERSION: u32 = 1;

/// One block's contribution to a fault: enough to check the signature and
/// tell it apart from another block, nothing that requires decoding `P`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAttestation {
    /// Hex-encoded (`0x...`) bytes the proposer actually signed.
    pub signing_bytes: String,
    /// Hex-encoded (`0x...`) Ed25519 signature over `signing_bytes`.
    pub signature: String,
    /// Hex-encoded (`0x...`) block hash — used only to prove the two blocks
    /// in an equivocation are actually distinct, not to derive anything.
    pub block_hash: String,
}

/// ponytail: one variant, because equivocation is the only fault this
/// codebase can currently produce (`xc_evidence::verify_equivocation`).
/// Tagged by `fault` so more variants (double-spend, invalid-state-transition,
/// ...) have an obvious place to land later, without breaking this one.
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
    /// Binds this artifact to one chain, so evidence from one network can't
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
    #[error("unsupported artifact_version {0}, this verifier knows version {ARTIFACT_VERSION}")]
    UnsupportedVersion(u32),
    #[error("{field} is not valid hex: {source}")]
    BadHex { field: &'static str, #[source] source: hex::FromHexError },
    #[error("proposer_pubkey must be 32 bytes, got {0}")]
    BadPubkeyLength(usize),
    #[error("proposer_pubkey does not decode to a valid Ed25519 public key")]
    BadPubkey,
    #[error("signature must be 64 bytes, got {0}")]
    BadSignatureLength(usize),
    #[error("the two cited blocks have the same block_hash, not distinct evidence")]
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
    hex::decode(s.trim_start_matches("0x")).map_err(|source| VerifyError::BadHex { field, source })
}

/// Verifies `artifact` is internally consistent: correct signatures, over
/// distinct blocks, by the pubkey it names. Never decodes `human_readable`
/// or any chain-specific payload — that's the whole point.
pub fn verify(artifact: &EvidenceArtifact) -> Result<Verdict, VerifyError> {
    if artifact.artifact_version != ARTIFACT_VERSION {
        return Err(VerifyError::UnsupportedVersion(artifact.artifact_version));
    }

    match &artifact.fault {
        Fault::Equivocation { proposer_pubkey, blocks, .. } => {
            let pubkey_bytes = decode_hex("proposer_pubkey", proposer_pubkey)?;
            let pubkey_bytes: [u8; 32] = pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadPubkeyLength(pubkey_bytes.len()))?;
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadPubkey)?;

            if blocks[0].block_hash == blocks[1].block_hash {
                return Err(VerifyError::SameBlock);
            }

            for (i, block) in blocks.iter().enumerate() {
                let signing_bytes = decode_hex("signing_bytes", &block.signing_bytes)?;
                let sig_bytes = decode_hex("signature", &block.signature)?;
                let sig_bytes: [u8; 64] = sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| VerifyError::BadSignatureLength(sig_bytes.len()))?;
                let signature = Signature::from_bytes(&sig_bytes);
                verifying_key
                    .verify(&signing_bytes, &signature)
                    .map_err(|_| VerifyError::SignatureInvalid(i))?;
            }

            Ok(Verdict { fault: "equivocation", culpable_pubkey: proposer_pubkey.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn attestation(key: &SigningKey, msg: &[u8]) -> BlockAttestation {
        let signature = key.sign(msg);
        BlockAttestation {
            signing_bytes: format!("0x{}", hex::encode(msg)),
            signature: format!("0x{}", hex::encode(signature.to_bytes())),
            block_hash: format!("0x{}", hex::encode(Sha256::digest(msg))),
        }
    }

    fn artifact(key: &SigningKey) -> EvidenceArtifact {
        EvidenceArtifact {
            artifact_version: ARTIFACT_VERSION,
            genesis_hash: "0xdeadbeef".to_string(),
            fault: Fault::Equivocation {
                proposer_pubkey: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
                height: 5,
                blocks: [attestation(key, b"block-a"), attestation(key, b"block-b")],
            },
            human_readable: serde_json::json!({"note": "non-normative"}),
        }
    }

    #[test]
    fn verify_accepts_valid_equivocation_artifact() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let verdict = verify(&artifact(&key)).unwrap();
        assert_eq!(verdict.fault, "equivocation");
        assert_eq!(verdict.culpable_pubkey, format!("0x{}", hex::encode(key.verifying_key().as_bytes())));
    }

    #[test]
    fn verify_rejects_tampered_signing_bytes() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut a = artifact(&key);
        let Fault::Equivocation { blocks, .. } = &mut a.fault;
        blocks[0].signing_bytes = format!("0x{}", hex::encode(b"tampered"));
        assert!(matches!(verify(&a), Err(VerifyError::SignatureInvalid(0))));
    }

    #[test]
    fn verify_rejects_same_block_cited_twice() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut a = artifact(&key);
        let Fault::Equivocation { blocks, .. } = &mut a.fault;
        blocks[1] = blocks[0].clone();
        assert!(matches!(verify(&a), Err(VerifyError::SameBlock)));
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut a = artifact(&key);
        a.artifact_version = 99;
        assert!(matches!(verify(&a), Err(VerifyError::UnsupportedVersion(99))));
    }

    #[test]
    fn round_trips_through_json() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let json = serde_json::to_string_pretty(&artifact(&key)).unwrap();
        assert!(json.contains("\"fault\": \"equivocation\""));
        let parsed: EvidenceArtifact = serde_json::from_str(&json).unwrap();
        verify(&parsed).unwrap();
    }
}
