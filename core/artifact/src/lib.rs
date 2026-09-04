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
//!
//! Design rule, learned the hard way three times over (`BlockAttestation`'s
//! now-removed `block_hash`, the height fields, and `DissentAttestation`'s
//! `header_commitment`): `xc-artifact` may only branch on values it
//! recomputes from signed bytes. Anything else belongs in `human_readable`.
//! A field that's merely *asserted* by the artifact — however authentically
//! signed — proves only that someone signed it, not that it's true of the
//! thing the verdict is about. If a field is load-bearing for a verdict and
//! isn't recomputable, the signing payload needs to change so it is.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Mirrors `xc_primitives::block::Block::round`.
    pub round: u32,
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
    round: u32,
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
        round: header.round,
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
    /// Opaque, chain-internal block hash — operational only (what the node
    /// indexes dissents by). Not recomputable from this artifact, so
    /// `verify()` never trusts it for the disagreement binding; that's what
    /// `header_commitment` is for.
    pub block_hash: String,
    /// State root the dissenter computed instead of the proposer's.
    pub state_root: String,
    /// Hex-encoded (`0x...`) `sha256(signing_bytes_for(header))` of the
    /// disputed block — cryptographically binds this dissent to the exact
    /// block, since `block_hash` alone can't be recomputed by a verifier who
    /// only holds this artifact.
    pub header_commitment: String,
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

const DOMAIN_DISSENT: &[u8] = b"arxium/dissent/v2";

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The exact bytes a dissenting validator signs — must match
/// `arxd_finality::dissent_signing_bytes` byte-for-byte. Pinned by
/// `frozen_dissent_signing_bytes_vector` below, its twin in
/// `arxd/finality/src/lib.rs`, and `dissent_signing_bytes_match_across_crates`
/// in `arxd/node/src/lib.rs` (the only crate that already depends on both),
/// mirroring `signing_bytes_for`/`CanonicalHeader` above.
pub fn dissent_signing_bytes(
    height: u64,
    block_hash: &str,
    state_root: &str,
    header_commitment: &[u8; 32],
    ep: &[u8; 32],
    reason: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_DISSENT);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, block_hash.as_bytes());
    push_field(&mut buf, state_root.as_bytes());
    push_field(&mut buf, header_commitment);
    push_field(&mut buf, ep);
    push_field(&mut buf, reason.as_bytes());
    buf
}

const DOMAIN_BLOCK_DIVERGENCE: &[u8] = b"arxium/block_divergence/v1";

/// The exact bytes a dissenter signs to stake a claim on a whole block's
/// final state root — `Fault::BlockDivergence`'s unilateral counterpart to
/// `action_claim_signing_bytes`. Binds height, the disputed block (via
/// `header_commitment` — `sha256(signing_bytes_for(header))`, same binding
/// `DissentAttestation` uses and for the same reason: an opaque block hash
/// can't be recomputed by a verifier holding only this artifact), the
/// agreed starting root, and the dissenter's own claimed final root.
pub fn block_divergence_signing_bytes(
    height: u64,
    header_commitment: &[u8; 32],
    parent_state_root: &str,
    computed_state_root: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_BLOCK_DIVERGENCE);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, header_commitment);
    push_field(&mut buf, parent_state_root.as_bytes());
    push_field(&mut buf, computed_state_root.as_bytes());
    buf
}

/// A dissenter's signed claim that replaying a whole block from the agreed
/// `parent_state_root` (see `Fault::BlockDivergence`) yields a different
/// final root than the proposer signed — no proposer cooperation needed,
/// unlike [`ActionClaim`]'s per-action commitment (see `Fault::ActionDivergence`'s
/// doc comment for why that one can't be built unilaterally). `verify()`
/// confirms the proofs are internally consistent against `parent_state_root`
/// and the signature is genuine; it cannot confirm `computed_state_root` is
/// what replaying the block's actions actually produces (that needs to
/// decode and run them — exactly what a payload-aware adjudicator in
/// `arx-verify` does).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDissentClaim {
    pub computed_state_root: String,
    /// [`StateProof`]s for every state key read or written anywhere in the
    /// block, each checked against `parent_state_root`.
    pub proofs: Vec<StateProof>,
    /// Hex-encoded (`0x...`) BLS signature over
    /// `block_divergence_signing_bytes(height, header_commitment,
    /// parent_state_root, computed_state_root)`.
    pub signature: String,
}

const DOMAIN_ACTION_CLAIM: &[u8] = b"arxium/action_claim/v1";

/// The exact bytes a party signs to stake a claim on one action's effect —
/// binds height, position in the block, the action's own content (via its
/// hash, not the full bytes, keeping this bounded regardless of action
/// size), and the claimed pre/post roots. Both `Fault::ActionDivergence`
/// claims sign this; `verify()` recomputes it independently rather than
/// trusting anything the artifact merely asserts, same rule as
/// `signing_bytes_for`/`dissent_signing_bytes` above.
pub fn action_claim_signing_bytes(
    height: u64,
    action_index: u64,
    action_bytes_hash: &[u8; 32],
    pre_state_root: &str,
    post_state_root: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_field(&mut buf, DOMAIN_ACTION_CLAIM);
    push_field(&mut buf, &height.to_le_bytes());
    push_field(&mut buf, &action_index.to_le_bytes());
    push_field(&mut buf, action_bytes_hash);
    push_field(&mut buf, pre_state_root.as_bytes());
    push_field(&mut buf, post_state_root.as_bytes());
    buf
}

/// One state key's proven membership (or non-membership) under an
/// [`ActionClaim`]'s `pre_state_root` — the wire shape of
/// `xc_poe::state_trie::InclusionProof`, hex-encoded and reimplemented here
/// rather than depending on `xc-poe` directly: that crate depends on
/// `xc-primitives` (for `xc_poe::tx_root`'s block hashing), and this crate's
/// one rule is no chain-shaped dependencies — see the module doc. Same
/// duplication-with-a-frozen-vector pattern as `dissent_signing_bytes`
/// above; `sibling_leaf_hash`/`sibling_internal_hash` below must stay
/// byte-for-byte identical to `xc_poe::state_trie`'s `leaf_hash`/
/// `internal_hash`, pinned by a cross-crate test in `arxd/node` (the only
/// crate that already depends on both).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    pub key_hash: String,
    /// `None` = a non-inclusion proof (the key is proven absent).
    pub value: Option<String>,
    /// 256 hex-encoded (`0x...`) 32-byte siblings, root-to-leaf order.
    pub siblings: Vec<String>,
}

/// One party's signed claim about a single disputed action: the state root
/// before and after it lands, plus [`StateProof`]s for every key it reads
/// or writes, each checked against `pre_state_root`. `verify()` confirms
/// the proofs are internally consistent and the signature is genuine — it
/// cannot confirm these are the *right* keys for the action (that needs to
/// decode the chain-specific payload) or that `post_state_root` is what
/// re-executing the action actually produces (that needs to run it). Both
/// are exactly what a payload-aware adjudicator built on top of this crate
/// does; see `Fault::ActionDivergence`'s doc comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionClaim {
    pub pre_state_root: String,
    pub post_state_root: String,
    pub proofs: Vec<StateProof>,
    /// Hex-encoded (`0x...`) signature over
    /// `action_claim_signing_bytes(height, action_index, action_bytes,
    /// pre_state_root, post_state_root)` — Ed25519 for the proposer's claim,
    /// BLS for the dissenter's, mirroring `BlockAttestation`/
    /// `DissentAttestation`'s asymmetry above.
    pub signature: String,
}

/// Four fault kinds today: equivocation (a proposer double-signed),
/// execution disagreement (a dissenter's honest re-execution diverged from
/// the proposer's claimed result but neither party has isolated *where*),
/// action divergence (interactive bisection's non-interactive result — a
/// dissenter has narrowed the disagreement to one specific action and both
/// parties have staked a signed claim on its effect; unused until the
/// bisection protocol itself lands, see the type's own doc comment), and
/// block divergence (the unilateral full-block fraud proof used instead,
/// today — see that type's doc comment for why). Tagged so more fault
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
    /// Like `ExecutionDisagreement`, `verify()` alone can only confirm a
    /// genuine, well-formed dispute over one specific action — never who's
    /// at fault (see `Verdict::Disagreement`). Naming a culprit means
    /// decoding `action_bytes` as the chain's payload type and re-executing
    /// it against the proven pre-state, which is inherently chain-specific
    /// and deliberately lives outside this crate (a feature-gated
    /// adjudicator in `arx-verify`, per the plan's "first real crack in
    /// `arx-verify`'s chain-agnosticism").
    ///
    /// Built for the interactive bisection path: a proposer signs an
    /// `ActionClaim` per action, on demand, and both sides narrow to the
    /// first divergent one over `O(log n)` challenge/response rounds. That
    /// protocol doesn't exist yet — a proposer signs only the block header
    /// today, never a per-action commitment — so this variant currently has
    /// no producer. `BlockDivergence` below is what's actually emitted in
    /// the meantime; this stays in the codebase, already written and
    /// tested, for when bisection lands as the size optimization over
    /// `BlockDivergence`'s whole-block proofs.
    ActionDivergence {
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the proposer.
        proposer_pubkey: String,
        /// Hex-encoded (`0x...`) raw BLS12-381 public key (48 bytes) of the dissenter.
        voter_pubkey: String,
        height: u64,
        /// Position of the disputed action in the block's action list.
        action_index: u64,
        /// Hex-encoded (`0x...`) bincode bytes of the disputed `Action<P>` —
        /// opaque to this crate; both claims sign over its hash, which is
        /// what actually binds a claim to this specific action.
        action_bytes: String,
        proposed_claim: ActionClaim,
        dissent_claim: ActionClaim,
    },
    /// A dissenter's unilateral fraud proof against a whole block: replaying
    /// every action from the agreed `parent_state_root` yields a state root
    /// different from the one the proposer actually signed in
    /// `block_attestation`. No cooperation from the proposer is needed —
    /// unlike `ActionDivergence`, the proposer's claim here is just their
    /// ordinary signed block header, the one per-block commitment they
    /// genuinely made. `verify()` alone can only confirm a genuine,
    /// well-formed dispute (see `Verdict::Disagreement`); naming a culprit
    /// means decoding and re-executing the block's actions against the
    /// proven pre-state, chain-specific work that lives in `arx-verify`.
    BlockDivergence {
        /// Hex-encoded (`0x...`) raw Ed25519 public key of the proposer.
        proposer_pubkey: String,
        /// Hex-encoded (`0x...`) raw BLS12-381 public key (48 bytes) of the dissenter.
        voter_pubkey: String,
        height: u64,
        /// Hex-encoded (`0x...`) state root both parties agree the block
        /// started from — the dissenter's proofs are checked against this,
        /// not against anything either party merely asserts about it.
        parent_state_root: String,
        /// The proposer's own signed block header — carries their claimed
        /// final `state_root` inside `header`, so this doubles as their
        /// claim; no separate `ActionClaim`-style signature is needed.
        block_attestation: BlockAttestation,
        /// Hex-encoded (`0x...`) bincode bytes of every action in the block,
        /// in order — opaque to this crate, same as `ActionDivergence`'s
        /// `action_bytes`. Not itself covered by any signature in this
        /// artifact (`verify()` doesn't decode `P` to compute a tx_root);
        /// a payload-aware adjudicator must recompute `tx_root` from these
        /// and check it against `block_attestation.header.tx_root` before
        /// trusting them as *the* actions the proposer signed for.
        actions: Vec<String>,
        dissent_claim: BlockDissentClaim,
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
    #[error("dissent claims height {dissent_height} but the proposed block is at height {fault_height}")]
    DisagreementHeightMismatch { dissent_height: u64, fault_height: u64 },
    #[error("proposed block signature does not verify against proposer_pubkey")]
    ProposedSignatureInvalid,
    #[error("voter_pubkey must be 48 bytes, got {0}")]
    BadBlsPubkeyLength(usize),
    #[error("signature must be 96 bytes, got {0}")]
    BadBlsSignatureLength(usize),
    #[error("ep must be 32 bytes, got {0}")]
    BadEpLength(usize),
    #[error("header_commitment must be 32 bytes, got {0}")]
    BadHeaderCommitmentLength(usize),
    #[error("dissent signature does not verify against voter_pubkey")]
    DissentSignatureInvalid,
    #[error("dissent's state_root is identical to the proposed block's — not a disagreement")]
    NoDisagreement,
    #[error("dissent's header_commitment does not match the proposed block's header — the dissent targets a different block")]
    DissentTargetsDifferentBlock,
    #[error("{field} must be {expected} bytes, got {len}")]
    BadFixedLength { field: &'static str, len: usize, expected: usize },
    #[error("a state proof must carry exactly 256 siblings")]
    BadProofShape,
    #[error("a state proof does not verify against its claim's pre_state_root")]
    StateProofDoesNotVerify,
    #[error("proposed_claim and dissent_claim disagree on pre_state_root — not a single-action divergence")]
    ActionClaimsDisagreeOnPreState,
    #[error("proposed_claim and dissent_claim agree on post_state_root — not a divergence")]
    ActionClaimsAgreeOnPostState,
    #[error("proposed_claim signature does not verify against proposer_pubkey")]
    ProposedClaimSignatureInvalid,
    #[error("dissent_claim signature does not verify against voter_pubkey")]
    DissentClaimSignatureInvalid,
    #[error("fault claims height {claimed} but block_attestation's header is at height {actual}")]
    BlockDivergenceHeightMismatch { claimed: u64, actual: u64 },
    #[error("block_attestation signature does not verify against proposer_pubkey")]
    BlockAttestationSignatureInvalid,
    #[error("dissent_claim signature does not verify against voter_pubkey")]
    BlockDissentSignatureInvalid,
    #[error("dissent_claim's computed_state_root is identical to the proposer's signed state_root — not a divergence")]
    BlockDivergenceNoDisagreement,
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
        round: 3,
    }
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, VerifyError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|source| VerifyError::BadHex { field, source })
}

fn decode_hex_32(field: &'static str, s: &str) -> Result<[u8; 32], VerifyError> {
    let bytes = decode_hex(field, s)?;
    bytes.as_slice().try_into().map_err(|_| VerifyError::BadFixedLength { field, len: bytes.len(), expected: 32 })
}

/// Sparse-Merkle-trie hash functions — must stay byte-for-byte identical to
/// `xc_poe::state_trie`'s `leaf_hash`/`internal_hash`. See [`StateProof`]'s
/// doc comment for why this crate carries its own copy instead of a
/// dependency, and `arxd_node::dissent_cross_crate_tests` (extended to cover
/// this pair too) for what actually enforces the two staying identical.
pub fn sibling_leaf_hash(key_hash: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(key_hash);
    hasher.update(value);
    hasher.finalize().into()
}

pub fn sibling_internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn sibling_bit_at(hash: &[u8; 32], level: usize) -> u8 {
    (hash[level / 8] >> (7 - level % 8)) & 1
}

/// Recomputes the root a [`StateProof`] implies and checks it equals
/// `root` — the same check as `xc_poe::state_trie::verify_proof`, just
/// operating on this crate's hex-encoded wire shape instead of raw bytes.
fn verify_state_proof(root: [u8; 32], proof: &StateProof) -> Result<(), VerifyError> {
    if proof.siblings.len() != 256 {
        return Err(VerifyError::BadProofShape);
    }
    let key_hash = decode_hex_32("key_hash", &proof.key_hash)?;
    let mut current = match &proof.value {
        Some(value) => sibling_leaf_hash(&key_hash, &decode_hex("proof value", value)?),
        // The all-zero 32-byte sentinel, matching `xc_poe::state_trie`'s
        // `default_hashes()[0]` — a leaf hash can never legitimately equal
        // it (it's the output of a hash function, astronomically unlikely
        // to land on all-zero), so this is safe to hardcode rather than
        // recomputing the 257-entry default table just for index 0.
        None => [0u8; 32],
    };
    for level in (0..256).rev() {
        let sibling = decode_hex_32("proof sibling", &proof.siblings[level])?;
        let (left, right) =
            if sibling_bit_at(&key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
        current = sibling_internal_hash(&left, &right);
    }
    if current != root {
        return Err(VerifyError::StateProofDoesNotVerify);
    }
    Ok(())
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
                    dissent_height: dissent.height,
                    fault_height: *height,
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

            let header_commitment_bytes = decode_hex("header_commitment", &dissent.header_commitment)?;
            let header_commitment_bytes: [u8; 32] = header_commitment_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadHeaderCommitmentLength(header_commitment_bytes.len()))?;
            if Sha256::digest(&bytes).as_slice() != header_commitment_bytes.as_slice() {
                return Err(VerifyError::DissentTargetsDifferentBlock);
            }

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
                ep_bytes.as_slice().try_into().map_err(|_| VerifyError::BadEpLength(ep_bytes.len()))?;

            let dissent_msg = dissent_signing_bytes(
                dissent.height,
                &dissent.block_hash,
                &dissent.state_root,
                &header_commitment_bytes,
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
        Fault::ActionDivergence {
            proposer_pubkey,
            voter_pubkey,
            height,
            action_index,
            action_bytes,
            proposed_claim,
            dissent_claim,
        } => {
            let pubkey_bytes = decode_hex_32("proposer_pubkey", proposer_pubkey)?;
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadPubkey)?;
            let voter_pubkey_bytes = decode_hex("voter_pubkey", voter_pubkey)?;
            let voter_pubkey_bytes: [u8; 48] = voter_pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsPubkeyLength(voter_pubkey_bytes.len()))?;
            let bls_voter_pubkey = BlsPublicKey(voter_pubkey_bytes);

            let action_bytes_raw = decode_hex("action_bytes", action_bytes)?;
            let action_bytes_hash: [u8; 32] = Sha256::digest(&action_bytes_raw).into();

            if proposed_claim.pre_state_root != dissent_claim.pre_state_root {
                return Err(VerifyError::ActionClaimsDisagreeOnPreState);
            }
            if proposed_claim.post_state_root == dissent_claim.post_state_root {
                return Err(VerifyError::ActionClaimsAgreeOnPostState);
            }

            let proposed_msg = action_claim_signing_bytes(
                *height,
                *action_index,
                &action_bytes_hash,
                &proposed_claim.pre_state_root,
                &proposed_claim.post_state_root,
            );
            let proposed_sig_bytes = decode_hex("proposed_claim signature", &proposed_claim.signature)?;
            let proposed_sig_bytes: [u8; 64] = proposed_sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadSignatureLength(proposed_sig_bytes.len()))?;
            verifying_key
                .verify(&proposed_msg, &Signature::from_bytes(&proposed_sig_bytes))
                .map_err(|_| VerifyError::ProposedClaimSignatureInvalid)?;

            let dissent_msg = action_claim_signing_bytes(
                *height,
                *action_index,
                &action_bytes_hash,
                &dissent_claim.pre_state_root,
                &dissent_claim.post_state_root,
            );
            let dissent_sig_bytes = decode_hex("dissent_claim signature", &dissent_claim.signature)?;
            let dissent_sig_bytes: [u8; 96] = dissent_sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsSignatureLength(dissent_sig_bytes.len()))?;
            xc_bls::verify(&dissent_msg, &bls_voter_pubkey, &BlsSignature(dissent_sig_bytes))
                .map_err(|_| VerifyError::DissentClaimSignatureInvalid)?;

            let proposed_root = decode_hex_32("proposed_claim.pre_state_root", &proposed_claim.pre_state_root)?;
            for proof in &proposed_claim.proofs {
                verify_state_proof(proposed_root, proof)?;
            }
            let dissent_root = decode_hex_32("dissent_claim.pre_state_root", &dissent_claim.pre_state_root)?;
            for proof in &dissent_claim.proofs {
                verify_state_proof(dissent_root, proof)?;
            }

            Ok(Verdict::Disagreement {
                fault: "action_divergence",
                parties: vec![proposer_pubkey.clone(), voter_pubkey.clone()],
            })
        }
        Fault::BlockDivergence {
            proposer_pubkey,
            voter_pubkey,
            height,
            parent_state_root,
            block_attestation,
            actions: _,
            dissent_claim,
        } => {
            let pubkey_bytes = decode_hex_32("proposer_pubkey", proposer_pubkey)?;
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadPubkey)?;
            let voter_pubkey_bytes = decode_hex("voter_pubkey", voter_pubkey)?;
            let voter_pubkey_bytes: [u8; 48] = voter_pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsPubkeyLength(voter_pubkey_bytes.len()))?;
            let bls_voter_pubkey = BlsPublicKey(voter_pubkey_bytes);

            if block_attestation.header.height != *height {
                return Err(VerifyError::BlockDivergenceHeightMismatch {
                    claimed: *height,
                    actual: block_attestation.header.height,
                });
            }

            let header_bytes = signing_bytes_for(&block_attestation.header)?;
            let sig_bytes = decode_hex("block_attestation signature", &block_attestation.signature)?;
            let sig_bytes: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadSignatureLength(sig_bytes.len()))?;
            verifying_key
                .verify(&header_bytes, &Signature::from_bytes(&sig_bytes))
                .map_err(|_| VerifyError::BlockAttestationSignatureInvalid)?;
            let header_commitment: [u8; 32] = Sha256::digest(&header_bytes).into();

            if block_attestation.header.state_root == dissent_claim.computed_state_root {
                return Err(VerifyError::BlockDivergenceNoDisagreement);
            }

            let dissent_msg = block_divergence_signing_bytes(
                *height,
                &header_commitment,
                parent_state_root,
                &dissent_claim.computed_state_root,
            );
            let dissent_sig_bytes = decode_hex("dissent_claim signature", &dissent_claim.signature)?;
            let dissent_sig_bytes: [u8; 96] = dissent_sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::BadBlsSignatureLength(dissent_sig_bytes.len()))?;
            xc_bls::verify(&dissent_msg, &bls_voter_pubkey, &BlsSignature(dissent_sig_bytes))
                .map_err(|_| VerifyError::BlockDissentSignatureInvalid)?;

            let parent_root = decode_hex_32("parent_state_root", parent_state_root)?;
            for proof in &dissent_claim.proofs {
                verify_state_proof(parent_root, proof)?;
            }

            Ok(Verdict::Disagreement {
                fault: "block_divergence",
                parties: vec![proposer_pubkey.clone(), voter_pubkey.clone()],
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
            round: 0,
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
            "2a0a30786465616462656566fc00ca9a3babababababababababababababababababababababababababababababababab3e6172783134323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323471357038766c790f30787374617465726f6f744861736803",
        );
    }

    /// Pins `dissent_signing_bytes`'s exact output against a hardcoded hex
    /// vector, twinned with `frozen_dissent_signing_bytes_vector` in
    /// `arxd/finality/src/lib.rs`. If either crate's encoding drifts from
    /// the other, one of the two copies fails loudly instead of silently —
    /// every previously-issued disagreement artifact would otherwise
    /// quietly stop verifying. `dissent_signing_bytes_match_across_crates`
    /// in `arxd/node/src/lib.rs` covers the same invariant directly (that
    /// crate depends on both), but a frozen vector also catches a drift
    /// where both crates change in lockstep to the same *wrong* answer.
    #[test]
    fn frozen_dissent_signing_bytes_vector() {
        let bytes = dissent_signing_bytes(
            5,
            "0xblockhash",
            "0xstateroot",
            &[9u8; 32],
            &[7u8; 32],
            "state_root_mismatch",
        );
        assert_eq!(
            hex::encode(&bytes),
            "110000000000000061727869756d2f64697373656e742f7632080000000000000005000000000000000b000000000000003078626c6f636b686173680b0000000000000030787374617465726f6f742000000000000000090909090909090909090909090909090909090909090909090909090909090920000000000000000707070707070707070707070707070707070707070707070707070707070707130000000000000073746174655f726f6f745f6d69736d61746368",
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
        disputed_header: &CanonicalHeader,
    ) -> DissentAttestation {
        let ep = [3u8; 32];
        let header_commitment: [u8; 32] =
            Sha256::digest(signing_bytes_for(disputed_header).unwrap()).into();
        let msg = dissent_signing_bytes(
            height,
            "0xblockhash",
            state_root,
            &header_commitment,
            &ep,
            "state_root_mismatch",
        );
        let signature = xc_bls::sign(voter_sk, &msg);
        DissentAttestation {
            height,
            block_hash: "0xblockhash".to_string(),
            state_root: state_root.to_string(),
            header_commitment: format!("0x{}", hex::encode(header_commitment)),
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
        let disputed_header = header(height, 1, "arx1proposer");
        let proposed = attestation(proposer_key, disputed_header.clone());
        let dissent =
            dissent_attestation(voter_sk, voter_pubkey, height, "0xdifferentstate", &disputed_header);
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

    /// The exploit this fix closes: a real dissent at height H, signed
    /// against block A, gets replayed alongside an unrelated but validly
    /// signed block B at the same height with a different state_root (e.g.
    /// from an equivocation). Without `header_commitment` binding, `verify()`
    /// would happily return `Disagreement` naming B's proposer, who the
    /// dissenter never actually objected to.
    #[test]
    fn dissent_targeting_different_block_is_rejected() {
        let proposer = SigningKey::from_bytes(&[7u8; 32]);
        let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
        let mut art = disagreement_artifact(&proposer, &voter_sk, &voter_pk, 5);
        // Swap in a validly-signed block at the same height with a different
        // tx_root — same shape as pairing a real dissent with an unrelated
        // equivocating block. The dissent's header_commitment still points
        // at the original header, so it no longer matches.
        if let Fault::ExecutionDisagreement { proposed, .. } = &mut art.fault {
            *proposed = attestation(&proposer, header(5, 99, "arx1proposer"));
        }
        assert!(matches!(verify(&art), Err(VerifyError::DissentTargetsDifferentBlock)));
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
        let disputed_header = header(5, 1, "arx1proposer");
        let proposed = attestation(&proposer, disputed_header.clone());
        // Dissenter's claimed state_root matches the proposer's ("0xstate", set by `header()`).
        let dissent = dissent_attestation(&voter_sk, &voter_pk, 5, "0xstate", &disputed_header);
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
        let disputed_header = header(5, 1, "arx1proposer");
        if let Fault::ExecutionDisagreement { dissent, .. } = &mut art.fault {
            *dissent = dissent_attestation(&voter_sk, &voter_pk, 99, "0xdifferentstate", &disputed_header);
        }
        assert!(matches!(
            verify(&art),
            Err(VerifyError::DisagreementHeightMismatch { dissent_height: 99, fault_height: 5 })
        ));
    }

    /// `dissent_signing_bytes` must be pure/deterministic and sensitive to
    /// every field, or two dissents that disagree in substance could collide
    /// onto the same signed message (or the same dissent re-encode
    /// differently between the signer and verifier).
    #[test]
    fn dissent_signing_bytes_is_deterministic_and_field_sensitive() {
        let base = dissent_signing_bytes(5, "0xblock", "0xstate", &[9u8; 32], &[1u8; 32], "state_root_mismatch");
        assert_eq!(
            base,
            dissent_signing_bytes(5, "0xblock", "0xstate", &[9u8; 32], &[1u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(6, "0xblock", "0xstate", &[9u8; 32], &[1u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(5, "0xother", "0xstate", &[9u8; 32], &[1u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(5, "0xblock", "0xother", &[9u8; 32], &[1u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(5, "0xblock", "0xstate", &[8u8; 32], &[1u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(5, "0xblock", "0xstate", &[9u8; 32], &[2u8; 32], "state_root_mismatch")
        );
        assert_ne!(
            base,
            dissent_signing_bytes(5, "0xblock", "0xstate", &[9u8; 32], &[1u8; 32], "action_mismatch")
        );
    }

    // `Fault::ActionDivergence` — Part 3 Stage 3's non-interactive
    // bisection result. These tests build proofs against the canonical
    // empty-trie root using this crate's own `sibling_*` functions (not
    // `xc_poe`'s — see `StateProof`'s doc comment for why this crate can't
    // depend on that crate), the same way `xc_poe::state_trie`'s own tests
    // hand-build proofs for isolated scenarios.
    mod action_divergence {
        use super::*;

        pub(super) fn default_hashes_for_tests() -> [[u8; 32]; 257] {
            let mut table = [[0u8; 32]; 257];
            for depth in 1..=256 {
                table[depth] = sibling_internal_hash(&table[depth - 1], &table[depth - 1]);
            }
            table
        }

        pub(super) fn empty_trie_root() -> [u8; 32] {
            default_hashes_for_tests()[256]
        }

        pub(super) fn empty_trie_state_proof(key_hash: [u8; 32]) -> StateProof {
            let defaults = default_hashes_for_tests();
            StateProof {
                key_hash: format!("0x{}", hex::encode(key_hash)),
                value: None,
                siblings: (0..256).map(|level| format!("0x{}", hex::encode(defaults[255 - level]))).collect(),
            }
        }

        /// The root after writing `value` into an otherwise-empty trie at
        /// `key_hash` — every sibling on the path is the untouched default,
        /// same hand-computation `xc_poe::state_trie`'s own tests use.
        pub(super) fn root_after_writing(key_hash: [u8; 32], value: &[u8]) -> [u8; 32] {
            let defaults = default_hashes_for_tests();
            let mut current = sibling_leaf_hash(&key_hash, value);
            for level in (0..256).rev() {
                let sibling = defaults[255 - level];
                let (left, right) =
                    if sibling_bit_at(&key_hash, level) == 0 { (current, sibling) } else { (sibling, current) };
                current = sibling_internal_hash(&left, &right);
            }
            current
        }

        pub(super) fn key_hash(seed: u8) -> [u8; 32] {
            Sha256::digest([seed]).into()
        }

        struct Fixture {
            proposer_key: SigningKey,
            voter_sk: xc_bls::BlsSecretKey,
            voter_pk: xc_bls::BlsPublicKey,
            action_bytes: Vec<u8>,
            height: u64,
            action_index: u64,
        }

        fn fixture() -> Fixture {
            let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
            Fixture {
                proposer_key: SigningKey::from_bytes(&[7u8; 32]),
                voter_sk,
                voter_pk,
                action_bytes: b"a bincode-encoded action, opaque to this crate".to_vec(),
                height: 5,
                action_index: 2,
            }
        }

        fn claim(
            fx: &Fixture,
            pre_root: [u8; 32],
            post_root: [u8; 32],
            proofs: Vec<StateProof>,
            signer: &dyn Fn(&[u8]) -> String,
        ) -> ActionClaim {
            let action_bytes_hash: [u8; 32] = Sha256::digest(&fx.action_bytes).into();
            let msg = action_claim_signing_bytes(
                fx.height,
                fx.action_index,
                &action_bytes_hash,
                &format!("0x{}", hex::encode(pre_root)),
                &format!("0x{}", hex::encode(post_root)),
            );
            ActionClaim {
                pre_state_root: format!("0x{}", hex::encode(pre_root)),
                post_state_root: format!("0x{}", hex::encode(post_root)),
                proofs,
                signature: signer(&msg),
            }
        }

        fn ed25519_signer(key: &SigningKey) -> impl Fn(&[u8]) -> String + '_ {
            move |msg| format!("0x{}", hex::encode(key.sign(msg).to_bytes()))
        }

        fn bls_signer<'a>(sk: &'a xc_bls::BlsSecretKey) -> impl Fn(&[u8]) -> String + 'a {
            move |msg| format!("0x{}", hex::encode(xc_bls::sign(sk, msg).0))
        }

        fn artifact_with(fx: &Fixture, proposed_claim: ActionClaim, dissent_claim: ActionClaim) -> EvidenceArtifact {
            EvidenceArtifact {
                artifact_version: ARTIFACT_VERSION,
                genesis_hash: "0xgenesis".to_string(),
                fault: Fault::ActionDivergence {
                    proposer_pubkey: format!("0x{}", hex::encode(fx.proposer_key.verifying_key().as_bytes())),
                    voter_pubkey: format!("0x{}", hex::encode(fx.voter_pk.0)),
                    height: fx.height,
                    action_index: fx.action_index,
                    action_bytes: format!("0x{}", hex::encode(&fx.action_bytes)),
                    proposed_claim,
                    dissent_claim,
                },
                human_readable: serde_json::json!({}),
            }
        }

        /// Straightforward divergence: both parties agree on the pre-state
        /// but claim different post-states, each with a valid proof and
        /// valid signature. `verify()` can confirm exactly this much — see
        /// the type's doc comment for why it stops at `Disagreement`.
        #[test]
        fn valid_action_divergence_verifies_as_disagreement() {
            let fx = fixture();
            let key = key_hash(1);
            let pre = empty_trie_root();
            let proposed_post = root_after_writing(key, b"proposer's value");
            let dissent_post = root_after_writing(key, b"dissenter's value");

            let proposed = claim(
                &fx, pre, proposed_post,
                vec![empty_trie_state_proof(key)],
                &ed25519_signer(&fx.proposer_key),
            );
            let dissent = claim(
                &fx, pre, dissent_post,
                vec![empty_trie_state_proof(key)],
                &bls_signer(&fx.voter_sk),
            );

            let verdict = verify(&artifact_with(&fx, proposed, dissent)).unwrap();
            assert!(matches!(verdict, Verdict::Disagreement { fault: "action_divergence", .. }));
        }

        #[test]
        fn claims_starting_from_different_pre_states_are_rejected() {
            let fx = fixture();
            let key = key_hash(1);
            let pre_a = empty_trie_root();
            let pre_b = root_after_writing(key_hash(9), b"some other prior write");

            let proposed = claim(
                &fx, pre_a, root_after_writing(key, b"x"),
                vec![empty_trie_state_proof(key)],
                &ed25519_signer(&fx.proposer_key),
            );
            let dissent = claim(
                &fx, pre_b, root_after_writing(key, b"y"),
                vec![], // pre_b's proof doesn't matter, this must fail before proofs are checked
                &bls_signer(&fx.voter_sk),
            );

            assert!(matches!(
                verify(&artifact_with(&fx, proposed, dissent)),
                Err(VerifyError::ActionClaimsDisagreeOnPreState)
            ));
        }

        #[test]
        fn claims_agreeing_on_post_state_are_not_a_divergence() {
            let fx = fixture();
            let key = key_hash(1);
            let pre = empty_trie_root();
            let post = root_after_writing(key, b"same value both sides");

            let proposed = claim(
                &fx, pre, post,
                vec![empty_trie_state_proof(key)],
                &ed25519_signer(&fx.proposer_key),
            );
            let dissent = claim(
                &fx, pre, post,
                vec![empty_trie_state_proof(key)],
                &bls_signer(&fx.voter_sk),
            );

            assert!(matches!(
                verify(&artifact_with(&fx, proposed, dissent)),
                Err(VerifyError::ActionClaimsAgreeOnPostState)
            ));
        }

        #[test]
        fn a_forged_proposed_claim_signature_is_rejected() {
            let fx = fixture();
            let other_key = SigningKey::from_bytes(&[8u8; 32]);
            let key = key_hash(1);
            let pre = empty_trie_root();

            let proposed = claim(
                &fx, pre, root_after_writing(key, b"x"),
                vec![empty_trie_state_proof(key)],
                &ed25519_signer(&other_key), // signed by the wrong key
            );
            let dissent = claim(
                &fx, pre, root_after_writing(key, b"y"),
                vec![empty_trie_state_proof(key)],
                &bls_signer(&fx.voter_sk),
            );

            assert!(matches!(
                verify(&artifact_with(&fx, proposed, dissent)),
                Err(VerifyError::ProposedClaimSignatureInvalid)
            ));
        }

        #[test]
        fn a_forged_dissent_claim_signature_is_rejected() {
            let fx = fixture();
            let (other_sk, _) = xc_bls::keygen_from_seed(&[22u8; 32]).unwrap();
            let key = key_hash(1);
            let pre = empty_trie_root();

            let proposed = claim(
                &fx, pre, root_after_writing(key, b"x"),
                vec![empty_trie_state_proof(key)],
                &ed25519_signer(&fx.proposer_key),
            );
            let dissent = claim(
                &fx, pre, root_after_writing(key, b"y"),
                vec![empty_trie_state_proof(key)],
                &bls_signer(&other_sk), // signed by the wrong key
            );

            assert!(matches!(
                verify(&artifact_with(&fx, proposed, dissent)),
                Err(VerifyError::DissentClaimSignatureInvalid)
            ));
        }

        /// A proof that doesn't actually chain up to the claim's own
        /// `pre_state_root` must be rejected — this is what stops a party
        /// from pairing a real signed claim with fabricated proofs.
        #[test]
        fn a_state_proof_that_does_not_verify_is_rejected() {
            let fx = fixture();
            let key = key_hash(1);
            let pre = empty_trie_root();

            let mut bad_proof = empty_trie_state_proof(key);
            bad_proof.siblings[0] = format!("0x{}", hex::encode([0xFFu8; 32]));

            let proposed = claim(
                &fx, pre, root_after_writing(key, b"x"),
                vec![bad_proof],
                &ed25519_signer(&fx.proposer_key),
            );
            let dissent = claim(
                &fx, pre, root_after_writing(key, b"y"),
                vec![empty_trie_state_proof(key)],
                &bls_signer(&fx.voter_sk),
            );

            assert!(matches!(
                verify(&artifact_with(&fx, proposed, dissent)),
                Err(VerifyError::StateProofDoesNotVerify)
            ));
        }
    }

    // `Fault::BlockDivergence` — the unilateral whole-block fraud proof.
    // Reuses `action_divergence`'s trie helpers (empty-trie root/proofs,
    // `key_hash`) since both build proofs against the same sparse-Merkle
    // shape; only the claim/signing side differs.
    mod block_divergence {
        use super::action_divergence::{empty_trie_root, empty_trie_state_proof, key_hash, root_after_writing};
        use super::*;

        struct Fixture {
            proposer_key: SigningKey,
            voter_sk: xc_bls::BlsSecretKey,
            voter_pk: xc_bls::BlsPublicKey,
            height: u64,
        }

        fn fixture() -> Fixture {
            let (voter_sk, voter_pk) = xc_bls::keygen_from_seed(&[11u8; 32]).unwrap();
            Fixture { proposer_key: SigningKey::from_bytes(&[7u8; 32]), voter_sk, voter_pk, height: 5 }
        }

        fn block_header(fx: &Fixture, state_root: &str) -> CanonicalHeader {
            CanonicalHeader {
                height: fx.height,
                parent_hash: "0xparent".to_string(),
                timestamp: 1234,
                tx_root: format!("0x{}", hex::encode([1u8; 32])),
                proposer: "arx1proposer".to_string(),
                state_root: state_root.to_string(),
                round: 0,
            }
        }

        fn block_attestation(fx: &Fixture, header: CanonicalHeader) -> BlockAttestation {
            let bytes = signing_bytes_for(&header).unwrap();
            let signature = fx.proposer_key.sign(&bytes);
            BlockAttestation { header, signature: format!("0x{}", hex::encode(signature.to_bytes())) }
        }

        fn dissent_claim(
            fx: &Fixture,
            header: &CanonicalHeader,
            parent_root: [u8; 32],
            computed_root: [u8; 32],
            proofs: Vec<StateProof>,
            signer: &xc_bls::BlsSecretKey,
        ) -> BlockDissentClaim {
            let header_bytes = signing_bytes_for(header).unwrap();
            let header_commitment: [u8; 32] = Sha256::digest(&header_bytes).into();
            let parent_state_root = format!("0x{}", hex::encode(parent_root));
            let computed_state_root = format!("0x{}", hex::encode(computed_root));
            let msg = block_divergence_signing_bytes(fx.height, &header_commitment, &parent_state_root, &computed_state_root);
            BlockDissentClaim {
                computed_state_root,
                proofs,
                signature: format!("0x{}", hex::encode(xc_bls::sign(signer, &msg).0)),
            }
        }

        fn artifact_with(
            fx: &Fixture,
            parent_state_root: String,
            block_attestation: BlockAttestation,
            dissent_claim: BlockDissentClaim,
        ) -> EvidenceArtifact {
            EvidenceArtifact {
                artifact_version: ARTIFACT_VERSION,
                genesis_hash: "0xgenesis".to_string(),
                fault: Fault::BlockDivergence {
                    proposer_pubkey: format!("0x{}", hex::encode(fx.proposer_key.verifying_key().as_bytes())),
                    voter_pubkey: format!("0x{}", hex::encode(fx.voter_pk.0)),
                    height: fx.height,
                    parent_state_root,
                    block_attestation,
                    actions: vec!["0xaabbcc".to_string()],
                    dissent_claim,
                },
                human_readable: serde_json::json!({}),
            }
        }

        #[test]
        fn valid_block_divergence_verifies_as_disagreement() {
            let fx = fixture();
            let key = key_hash(1);
            let parent = empty_trie_root();
            let proposer_post = root_after_writing(key, b"proposer's block result");
            let dissent_post = root_after_writing(key, b"dissenter's block result");

            let header = block_header(&fx, &format!("0x{}", hex::encode(proposer_post)));
            let attestation = block_attestation(&fx, header.clone());
            let dissent = dissent_claim(
                &fx, &header, parent, dissent_post, vec![empty_trie_state_proof(key)], &fx.voter_sk,
            );

            let verdict =
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)).unwrap();
            assert!(matches!(verdict, Verdict::Disagreement { fault: "block_divergence", .. }));
        }

        #[test]
        fn matching_final_roots_are_not_a_divergence() {
            let fx = fixture();
            let key = key_hash(1);
            let parent = empty_trie_root();
            let post = root_after_writing(key, b"same result both sides");

            let header = block_header(&fx, &format!("0x{}", hex::encode(post)));
            let attestation = block_attestation(&fx, header.clone());
            let dissent =
                dissent_claim(&fx, &header, parent, post, vec![empty_trie_state_proof(key)], &fx.voter_sk);

            assert!(matches!(
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)),
                Err(VerifyError::BlockDivergenceNoDisagreement)
            ));
        }

        #[test]
        fn a_forged_block_attestation_signature_is_rejected() {
            let fx = fixture();
            let other_key = SigningKey::from_bytes(&[8u8; 32]);
            let key = key_hash(1);
            let parent = empty_trie_root();

            let header = block_header(&fx, &format!("0x{}", hex::encode(root_after_writing(key, b"x"))));
            let header_bytes = signing_bytes_for(&header).unwrap();
            let forged_signature = other_key.sign(&header_bytes);
            let attestation =
                BlockAttestation { header: header.clone(), signature: format!("0x{}", hex::encode(forged_signature.to_bytes())) };
            let dissent = dissent_claim(
                &fx, &header, parent, root_after_writing(key, b"y"), vec![empty_trie_state_proof(key)], &fx.voter_sk,
            );

            assert!(matches!(
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)),
                Err(VerifyError::BlockAttestationSignatureInvalid)
            ));
        }

        #[test]
        fn a_forged_dissent_claim_signature_is_rejected() {
            let fx = fixture();
            let (other_sk, _) = xc_bls::keygen_from_seed(&[22u8; 32]).unwrap();
            let key = key_hash(1);
            let parent = empty_trie_root();

            let header = block_header(&fx, &format!("0x{}", hex::encode(root_after_writing(key, b"x"))));
            let attestation = block_attestation(&fx, header.clone());
            let dissent = dissent_claim(
                &fx, &header, parent, root_after_writing(key, b"y"), vec![empty_trie_state_proof(key)], &other_sk,
            );

            assert!(matches!(
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)),
                Err(VerifyError::BlockDissentSignatureInvalid)
            ));
        }

        /// The exploit this binding closes: a dissent built for one block at
        /// height H gets replayed against a *different* validly-signed block
        /// at the same height (e.g. from an equivocation) — without
        /// `header_commitment` folded into the signed message, `verify()`
        /// would accept it as a divergence against a proposer the dissenter
        /// never actually disputed.
        #[test]
        fn a_dissent_claim_signed_for_a_different_block_is_rejected() {
            let fx = fixture();
            let key = key_hash(1);
            let parent = empty_trie_root();

            let real_header = block_header(&fx, &format!("0x{}", hex::encode(root_after_writing(key, b"x"))));
            let other_header = block_header(&fx, &format!("0x{}", hex::encode(root_after_writing(key, b"z"))));
            let attestation = block_attestation(&fx, real_header);
            // Dissent signed against `other_header`'s commitment, paired with
            // an attestation for `real_header`.
            let dissent = dissent_claim(
                &fx, &other_header, parent, root_after_writing(key, b"y"), vec![empty_trie_state_proof(key)], &fx.voter_sk,
            );

            assert!(matches!(
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)),
                Err(VerifyError::BlockDissentSignatureInvalid)
            ));
        }

        #[test]
        fn a_state_proof_that_does_not_verify_against_parent_root_is_rejected() {
            let fx = fixture();
            let key = key_hash(1);
            let parent = empty_trie_root();

            let mut bad_proof = empty_trie_state_proof(key);
            bad_proof.siblings[0] = format!("0x{}", hex::encode([0xFFu8; 32]));

            let header = block_header(&fx, &format!("0x{}", hex::encode(root_after_writing(key, b"x"))));
            let attestation = block_attestation(&fx, header.clone());
            let dissent =
                dissent_claim(&fx, &header, parent, root_after_writing(key, b"y"), vec![bad_proof], &fx.voter_sk);

            assert!(matches!(
                verify(&artifact_with(&fx, format!("0x{}", hex::encode(parent)), attestation, dissent)),
                Err(VerifyError::StateProofDoesNotVerify)
            ));
        }
    }
}
