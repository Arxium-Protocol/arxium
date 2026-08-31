// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Evidence artifact format: a self-describing, JSON-encoded proof of a
//! consensus fault, plus a `verify()` function that checks it without
//! decoding any chain-specific payload.
//!
//! Deliberately depends on nothing chain-shaped (no `xc-primitives`, no
//! storage, no node code) and encodes as JSON, not bincode: an artifact may
//! be read by a stranger, possibly years from now, possibly not in Rust. It
//! must stand on its own. The one exception is `xc-bls`, itself a
//! chain-agnostic crypto primitive (BLS12-381 signing/verification, no
//! consensus or storage of its own) — needed to verify a `Dissent`'s
//! signature for `Fault::ExecutionDisagreement`.
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
use xc_bls::{BlsPublicKey, BlsSignature};

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

/// Recomputes the exact bytes a proposer signs for `header` — byte-for-byte
/// the same encoding as `xc_primitives::block::Block::signing_bytes`
/// produces for the equivalent block (pinned by a cross-crate test in
/// `core/primitives`, since this crate deliberately can't depend on
/// `xc-primitives` to enforce that with the type system). Public because
/// it's genuinely useful to anyone implementing a verifier outside this
/// codebase, in another language: it's the one function that defines what
/// "signing bytes" means for this format.
pub fn signing_bytes_for(header: &CanonicalHeader) -> Result<Vec<u8>, VerifyError> {
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
    // Every field is a primitive or `&str`/`&[u8; 32]` — no user `Serialize`
    // impl in the payload, so bincode encoding has nothing to fail on.
    Ok(bincode::serde::encode_to_vec(&payload, config)
        .expect("SigningPayload is all primitives/&str, encoding cannot fail"))
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

/// A dissenting validator's signed claim that it independently executed a
/// block and got a different result — the counterpart to a proposer's
/// `BlockAttestation` for `Fault::ExecutionDisagreement`. Signing bytes are
/// reimplemented here to byte-for-byte match `arxd_finality::dissent_signing_bytes`
/// (same cross-crate duplication pattern as `signing_bytes_for` above, since
/// this crate can't depend on `arxd-finality`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissentAttestation {
    pub height: u64,
    pub block_hash: String,
    /// State root the dissenter computed instead of the proposer's.
    pub state_root: String,
    /// Hex-encoded (`0x...`) 32-byte execution proof the dissenter computed.
    pub ep: String,
    /// Machine-readable reason tag (e.g. `"state_root_mismatch"`), the same
    /// string `arxd_finality::DissentReason::as_str()` produces.
    pub reason: String,
    /// Bech32 address of the dissenting validator.
    pub voter: String,
    /// Hex-encoded (`0x...`) raw BLS12-381 public key (48 bytes) of the dissenter.
    pub voter_pubkey: String,
    /// Hex-encoded (`0x...`) BLS signature (96 bytes) over `dissent_signing_bytes`.
    pub signature: String,
}

const DOMAIN_DISSENT: &[u8] = b"arxium/dissent/v1";

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The exact bytes a dissenting validator signs — must match
/// `arxd_finality::dissent_signing_bytes` byte-for-byte (pinned by a frozen
/// vector test in each crate, mirroring `signing_bytes_for`/`CanonicalHeader`
/// above).
pub fn dissent_signing_bytes(
    height: u64,
    block_hash: &str,
    state_root: &str,
    ep: &[u8; 32],
    reason: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_DISSENT);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, block_hash.as_bytes());
    push_field(&mut buf, state_root.as_bytes());
    push_field(&mut buf, ep);
    push_field(&mut buf, reason.as_bytes());
    buf
}

/// Two fault kinds today: equivocation (a proposer double-signed) and
/// execution disagreement (a dissenter's honest re-execution diverged from
/// the proposer's claimed result — see module docs for why this crate can
/// verify the dispute exists but not who's at fault). Tagged so more fault
/// types have an obvious place to land later without breaking these.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum Fault {
    Equivocation {
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the culpable proposer.
        proposer_pubkey: String,
        height: u64,
        blocks: [BlockAttestation; 2],
    },
    /// Deliberately does not name a culpable party: this artifact proves a
    /// proposer and a validator disagree about execution, not which of them
    /// is wrong. See `Verdict::Disagreement`.
    ExecutionDisagreement {
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the proposer.
        proposer_pubkey: String,
        height: u64,
        proposed: BlockAttestation,
        dissent: DissentAttestation,
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
    #[error("dissent claims height {claimed} but the proposed block is at height {actual}")]
    DisagreementHeightMismatch { claimed: u64, actual: u64 },
    #[error("proposed block signature does not verify against proposer_pubkey")]
    ProposedSignatureInvalid,
    #[error("voter_pubkey must be 48 bytes, got {0}")]
    BadBlsPubkeyLength(usize),
    #[error("signature must be 96 bytes, got {0}")]
    BadBlsSignatureLength(usize),
    #[error("dissent signature does not verify against voter_pubkey")]
    DissentSignatureInvalid,
    #[error("dissent's state_root is identical to the proposed block's — not a disagreement")]
    NoDisagreement,
}

/// What a verified artifact proves, once `verify()` accepts it. Two shapes:
/// `verify()` either names exactly who is at fault (`Culpable`, today only
/// from equivocation, where both signatures came from the same key), or
/// confirms a genuine dispute exists without resolving it (`Disagreement`,
/// from execution disagreement — a proposer and a validator each signed a
/// different result, and only re-execution by a third party can say who's
/// right).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Culpable {
        fault: &'static str,
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the culpable party.
        culpable_pubkey: String,
    },
    Disagreement {
        fault: &'static str,
        /// Hex-encoded (`0x...`) identifiers of the disagreeing parties:
        /// `[proposer_pubkey, voter_pubkey]`.
        parties: Vec<String>,
    },
}

/// The fixed header used to pin `signing_bytes_for`'s encoding against
/// `xc_primitives::block::Block::signing_bytes` — see
/// `frozen_signing_bytes_vector` below and its twin in
/// `core/primitives/src/block.rs`. Exposed (not `#[cfg(test)]`) so the
/// cross-crate test can build the identical header without duplicating
/// these literals and risking the two copies drifting apart.
pub fn frozen_test_header() -> CanonicalHeader {
    CanonicalHeader {
        height: 42,
        parent_hash: "0xdeadbeef".to_string(),
        timestamp: 1_000_000_000,
        tx_root: format!("0x{}", "ab".repeat(32)),
        // `xc_primitives::Address::from_pubkey_bytes(&[0xaa; 32])` — hardcoded
        // (not computed) since this crate has no bech32 dependency and must
        // not gain one just for a test fixture.
        proposer: "arx1424242424242424242424242424242424242424242424242424q5p8vly".to_string(),
        state_root: "0xstaterootHash".to_string(),
    }
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
                let bytes = signing_bytes_for(&block.header)?;
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

            Ok(Verdict::Culpable { fault: "equivocation", culpable_pubkey: proposer_pubkey.clone() })
        }
        Fault::ExecutionDisagreement { proposer_pubkey, height, proposed, dissent } => {
            let pubkey_bytes = decode_hex("proposer_pubkey", proposer_pubkey)?;
            let pubkey_bytes: [u8; 32] = pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadPubkeyLength(pubkey_bytes.len()))?;
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadPubkey)?;

            if proposed.header.height != *height {
                return Err(VerifyError::FaultHeightMismatch {
                    claimed: *height,
                    actual: proposed.header.height,
                });
            }
            if dissent.height != *height {
                return Err(VerifyError::DisagreementHeightMismatch {
                    claimed: dissent.height,
                    actual: *height,
                });
            }

            let bytes = signing_bytes_for(&proposed.header)?;
            let sig_bytes = decode_hex("signature", &proposed.signature)?;
            let sig_bytes: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadSignatureLength(sig_bytes.len()))?;
            let signature = Signature::from_bytes(&sig_bytes);
            verifying_key.verify(&bytes, &signature).map_err(|_| VerifyError::ProposedSignatureInvalid)?;

            if proposed.header.state_root == dissent.state_root {
                return Err(VerifyError::NoDisagreement);
            }

            let voter_pubkey_bytes = decode_hex("voter_pubkey", &dissent.voter_pubkey)?;
            let voter_pubkey_bytes: [u8; 48] = voter_pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsPubkeyLength(voter_pubkey_bytes.len()))?;
            let voter_pubkey = BlsPublicKey(voter_pubkey_bytes);

            let dissent_sig_bytes = decode_hex("signature", &dissent.signature)?;
            let dissent_sig_bytes: [u8; 96] = dissent_sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsSignatureLength(dissent_sig_bytes.len()))?;
            let dissent_signature = BlsSignature(dissent_sig_bytes);

            let ep_bytes = decode_hex("ep", &dissent.ep)?;
            let ep_bytes: [u8; 32] =
                ep_bytes.as_slice().try_into().map_err(|_| VerifyError::BadPubkeyLength(ep_bytes.len()))?;

            let dissent_msg = dissent_signing_bytes(
                dissent.height,
                &dissent.block_hash,
                &dissent.state_root,
                &ep_bytes,
                &dissent.reason,
            );
            xc_bls::verify(&dissent_msg, &voter_pubkey, &dissent_signature)
                .map_err(|_| VerifyError::DissentSignatureInvalid)?;

            Ok(Verdict::Disagreement {
                fault: "execution_disagreement",
                parties: vec![proposer_pubkey.clone(), dissent.voter_pubkey.clone()],
            })
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
        let bytes = signing_bytes_for(&header).unwrap();
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
        assert!(matches!(verdict, Verdict::Culpable { fault: "equivocation", .. }));
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

    /// Pins the exact bytes `signing_bytes_for` produces for one fixed
    /// header. This is the format spec, not just a test: the identical
    /// header + identical assertion also lives in
    /// `core/primitives/src/block.rs` (`frozen_signing_bytes_vector`),
    /// checked against `Block::signing_bytes`. If either crate's encoding
    /// drifts from the other, one of the two copies of this test fails
    /// loudly and points at exactly what changed — the alternative is a
    /// change that silently makes every previously-issued artifact
    /// unverifiable.
    #[test]
    fn frozen_signing_bytes_vector() {
        let header = frozen_test_header();
        let bytes = signing_bytes_for(&header).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "2a0a30786465616462656566fc00ca9a3babababababababababababababababababababababababababababababababab3e6172783134323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323471357038766c790f30787374617465726f6f7448617368",
        );
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

    fn dissent_attestation(
        voter_sk: &xc_bls::BlsSecretKey,
        voter_pubkey: &xc_bls::BlsPublicKey,
        height: u64,
        state_root: &str,
    ) -> DissentAttestation {
        let ep = [3u8; 32];
        let msg = dissent_signing_bytes(height, "0xblockhash", state_root, &ep, "state_root_mismatch");
        let signature = xc_bls::sign(voter_sk, &msg);
        DissentAttestation {
            height,
            block_hash: "0xblockhash".to_string(),
            state_root: state_root.to_string(),
            ep: format!("0x{}", hex::encode(ep)),
            reason: "state_root_mismatch".to_string(),
            voter: "arx1voter".to_string(),
            voter_pubkey: format!("0x{}", hex::encode(voter_pubkey.0)),
            signature: format!("0x{}", hex::encode(signature.0)),
        }
    }

    fn disagreement_artifact(
        proposer_key: &SigningKey,
        voter_sk: &xc_bls::BlsSecretKey,
        voter_pubkey: &xc_bls::BlsPublicKey,
        height: u64,
    ) -> EvidenceArtifact {
        let proposed = attestation(proposer_key, header(height, 1, "arx1proposer"));
        let dissent = dissent_attestation(voter_sk, voter_pubkey, height, "0xdifferentstate");
        EvidenceArtifact {
            artifact_version: ARTIFACT_VERSION,
            genesis_hash: "0xgenesis".to_string(),
            fault: Fault::ExecutionDisagreement {
                proposer_pubkey: format!("0x{}", hex::encode(proposer_key.verifying_key().as_bytes())),
                height,
                proposed,
                dissent,
            },
            human_readable: serde_json::json!({}),
        }
    }

    #[test]
    fn valid_execution_disagreement_verifies_as_disagreement_not_culpable() {
        let proposer = SigningKey::from_bytes(&[7u8; 32]);
        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let art = disagreement_artifact(&proposer, &voter_sk, &voter_pk, 5);
        let verdict = verify(&art).unwrap();
        match verdict {
            Verdict::Disagreement { fault: "execution_disagreement", parties } => {
                assert_eq!(parties.len(), 2);
            }
            other => panic!("expected Disagreement, got {other:?}"),
        }
    }

    #[test]
    fn forged_dissent_signature_is_rejected() {
        let proposer = SigningKey::from_bytes(&[7u8; 32]);
        let (_, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let (other_sk, _) = xc_bls::keygen_from_seed(&[22u8; 32]).unwrap();
        // Sign with a different key than the one named as voter_pubkey.
        let art = disagreement_artifact(&proposer, &other_sk, &voter_pk, 5);
        assert!(matches!(verify(&art), Err(VerifyError::DissentSignatureInvalid)));
    }

    #[test]
    fn matching_state_roots_are_not_a_disagreement() {
        let proposer = SigningKey::from_bytes(&[7u8; 32]);
        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let proposed = attestation(&proposer, header(5, 1, "arx1proposer"));
        // Dissenter's claimed state_root matches the proposer's ("0xstate", set by `header()`).
        let dissent = dissent_attestation(&voter_sk, &voter_pk, 5, "0xstate");
        let art = EvidenceArtifact {
            artifact_version: ARTIFACT_VERSION,
            genesis_hash: "0xgenesis".to_string(),
            fault: Fault::ExecutionDisagreement {
                proposer_pubkey: format!("0x{}", hex::encode(proposer.verifying_key().as_bytes())),
                height: 5,
                proposed,
                dissent,
            },
            human_readable: serde_json::json!({}),
        };
        assert!(matches!(verify(&art), Err(VerifyError::NoDisagreement)));
    }

    #[test]
    fn disagreement_height_must_match() {
        let proposer = SigningKey::from_bytes(&[7u8; 32]);
        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        // Dissent signs height 99 while the proposed block and Fault claim height 5.
        let mut art = disagreement_artifact(&proposer, &voter_sk, &voter_pk, 5);
        if let Fault::ExecutionDisagreement { dissent, .. } = &mut art.fault {
            *dissent = dissent_attestation(&voter_sk, &voter_pk, 99, "0xdifferentstate");
        }
        assert!(matches!(
            verify(&art),
            Err(VerifyError::DisagreementHeightMismatch { claimed: 99, actual: 5 })
        ));
    }

    /// `dissent_signing_bytes` must be pure/deterministic and sensitive to
    /// every field, or two dissents that disagree in substance could collide
    /// onto the same signed message (or the same dissent re-encode
    /// differently between the signer and verifier).
    #[test]
    fn dissent_signing_bytes_is_deterministic_and_field_sensitive() {
        let base = dissent_signing_bytes(5, "0xblock", "0xstate", &[1u8; 32], "state_root_mismatch");
        assert_eq!(base, dissent_signing_bytes(5, "0xblock", "0xstate", &[1u8; 32], "state_root_mismatch"));
        assert_ne!(base, dissent_signing_bytes(6, "0xblock", "0xstate", &[1u8; 32], "state_root_mismatch"));
        assert_ne!(base, dissent_signing_bytes(5, "0xother", "0xstate", &[1u8; 32], "state_root_mismatch"));
        assert_ne!(base, dissent_signing_bytes(5, "0xblock", "0xother", &[1u8; 32], "state_root_mismatch"));
        assert_ne!(base, dissent_signing_bytes(5, "0xblock", "0xstate", &[2u8; 32], "state_root_mismatch"));
        assert_ne!(base, dissent_signing_bytes(5, "0xblock", "0xstate", &[1u8; 32], "action_mismatch"));
    }
}
