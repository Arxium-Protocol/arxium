// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::Address;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// `P` is the chain-specific action payload (e.g. CoreChain's `ActionPayload`
/// or a spoke chain's own enum) — `Action` itself only knows about the
/// envelope: who sent it, at what nonce, signed how.
#[derive(Clone, Debug)]
pub struct Action<P> {
    pub sender: Address,
    pub nonce: u64,
    pub signature: Option<String>,
    pub payload: P,
}

/// The wire shape `Action<P>` actually serializes as, for any `P` — payload
/// pre-encoded into its own length-prefixed byte string rather than inlined
/// via `P`'s own `Serialize` impl. A plain derive encodes an enum payload as
/// a bare variant index with no length, so a reader whose copy of `P` is
/// missing a variant (e.g. an external indexer's hand-mirrored payload enum,
/// see `Retracer_Design.md`) can't tell how many bytes to skip and fails the
/// whole action. Length-prefixing the payload makes it skippable: see
/// [`RawAction`], which parses this exact shape without needing to know `P`
/// at all.
#[derive(Serialize, Deserialize)]
struct ActionWire<Payload> {
    sender: Address,
    nonce: u64,
    signature: Option<String>,
    payload: Payload,
}

impl<P: Serialize> Serialize for Action<P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload_bytes = bincode::serde::encode_to_vec(&self.payload, crate::wire_config())
            .map_err(S::Error::custom)?;
        ActionWire {
            sender: self.sender.clone(),
            nonce: self.nonce,
            signature: self.signature.clone(),
            payload: payload_bytes,
        }
        .serialize(serializer)
    }
}

impl<'de, P: serde::de::DeserializeOwned> Deserialize<'de> for Action<P> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire: ActionWire<Vec<u8>> = ActionWire::deserialize(deserializer)?;
        let (payload, consumed): (P, usize) =
            bincode::serde::decode_from_slice(&wire.payload, crate::wire_config())
                .map_err(D::Error::custom)?;
        if consumed != wire.payload.len() {
            return Err(D::Error::custom("trailing bytes after action payload"));
        }
        Ok(Action {
            sender: wire.sender,
            nonce: wire.nonce,
            signature: wire.signature,
            payload,
        })
    }
}

/// Same wire shape [`Action<P>`] always serializes as (sender, nonce,
/// signature, length-prefixed payload bytes), captured without attempting to
/// decode the payload into any concrete type. For an external reader (e.g.
/// an indexer) whose payload enum may lag the producing chain's: decode a
/// block's actions as `RawAction` first (always succeeds structurally),
/// then attempt each action's own payload bytes against the reader's own
/// payload type, skipping the ones that don't decode instead of failing the
/// whole block. See `RawBlock` in `block.rs` for the block-level counterpart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawAction {
    pub sender: Address,
    pub nonce: u64,
    pub signature: Option<String>,
    pub payload: Vec<u8>,
}

/// What actually gets signed: sender + nonce + payload, deterministically
/// encoded. The signature field itself is excluded (it can't sign itself).
#[derive(Serialize)]
struct SigningPayload<'a, P> {
    sender: &'a Address,
    nonce: u64,
    payload: &'a P,
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("action has no signature")]
    Missing,
    #[error("signature is not valid hex")]
    InvalidHex,
    #[error("signature must be 64 bytes, got {0}")]
    WrongLength(usize),
    #[error("sender address does not decode to a valid ed25519 pubkey: {0}")]
    BadPubkey(#[from] crate::AddressError),
    #[error("signature does not verify against sender and action contents")]
    Invalid,
    #[error("malformed multisig witness: {0}")]
    BadMultisig(&'static str),
}

impl<P: Serialize> Action<P> {
    /// Deterministic bytes that a valid signature must cover.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let payload = SigningPayload {
            sender: &self.sender,
            nonce: self.nonce,
            payload: &self.payload,
        };
        bincode::serde::encode_to_vec(&payload, crate::wire_config())
            .expect("signing payload encoding should never fail")
    }

    /// Verifies `signature` was produced by the private key behind `sender`,
    /// over this action's (sender, nonce, payload). `verify_strict`, not
    /// `verify`: addresses are raw pubkeys, and the small-order points
    /// (`arx1qqq…` among them) pass cofactored verification for any
    /// message — a funded one would be everyone's to spend.
    ///
    /// A multisig sender (see [`multisig_address`]) carries its policy and
    /// exactly `threshold` member signatures in the same hex `signature`
    /// field, so the wire shape (and `tx_root`, `RawAction`, indexers) is
    /// unchanged. Every `require_admin`/`require_issuer` style check compares
    /// `sender` only, so it gets M-of-N for free once this passes.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        let sig_hex = self.signature.as_deref().ok_or(SignatureError::Missing)?;
        let sig_bytes = hex::decode(sig_hex).map_err(|_| SignatureError::InvalidHex)?;
        let sender_bytes = self.sender.pubkey_bytes()?;
        if sender_bytes.len() == 33 && sender_bytes[0] == MULTISIG_TAG {
            return verify_multisig(&sender_bytes[1..], &sig_bytes, &self.signing_bytes());
        }
        verify_one(&sender_bytes, &sig_bytes, &self.signing_bytes())
    }
}

fn verify_one(pubkey: &[u8], sig: &[u8], message: &[u8]) -> Result<(), SignatureError> {
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| SignatureError::WrongLength(sig.len()))?;
    let pubkey: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| SignatureError::WrongLength(pubkey.len()))?;
    VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| SignatureError::Invalid)?
        .verify_strict(message, &Signature::from_bytes(&sig))
        .map_err(|_| SignatureError::Invalid)
}

/// First byte of a multisig address's 33 bech32 data bytes. A plain address
/// is 32 bytes, so the two can never collide.
const MULTISIG_TAG: u8 = 0x01;
/// Caps both the witness size and the verify work one action can demand.
pub const MAX_MULTISIG_MEMBERS: usize = 16;
const MULTISIG_DOMAIN: &[u8] = b"arxium-multisig-v1";

/// `sha256(domain ‖ threshold ‖ n ‖ members…)` — members must already be
/// strictly ascending, so one member set has exactly one address.
fn policy_hash(threshold: u8, members: &[[u8; 32]]) -> Result<[u8; 32], SignatureError> {
    if members.is_empty() || members.len() > MAX_MULTISIG_MEMBERS {
        return Err(SignatureError::BadMultisig("member count must be 1..=16"));
    }
    if threshold == 0 || usize::from(threshold) > members.len() {
        return Err(SignatureError::BadMultisig("threshold must be 1..=members"));
    }
    if members.windows(2).any(|w| w[0] >= w[1]) {
        return Err(SignatureError::BadMultisig(
            "members must be unique and ascending",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(MULTISIG_DOMAIN);
    hasher.update([threshold, members.len() as u8]);
    for m in members {
        hasher.update(m);
    }
    Ok(hasher.finalize().into())
}

fn sorted(members: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut members = members.to_vec();
    members.sort_unstable();
    members
}

/// The `threshold`-of-`members` address. Member order doesn't matter.
pub fn multisig_address(threshold: u8, members: &[[u8; 32]]) -> Result<Address, SignatureError> {
    let hash = policy_hash(threshold, &sorted(members))?;
    let mut bytes = vec![MULTISIG_TAG];
    bytes.extend_from_slice(&hash);
    Ok(Address::from_pubkey_bytes(&bytes)?)
}

/// Assembles the `signature` field for a multisig sender:
/// `threshold ‖ n ‖ members(32·n) ‖ threshold × (member index ‖ sig(64))`,
/// hex. `signatures` are (member pubkey, signature over `signing_bytes`),
/// each member signing exactly as a single-key sender would.
pub fn multisig_signature(
    threshold: u8,
    members: &[[u8; 32]],
    signatures: &[([u8; 32], [u8; 64])],
) -> Result<String, SignatureError> {
    let members = sorted(members);
    policy_hash(threshold, &members)?;
    let mut indexed = signatures
        .iter()
        .map(|(pk, sig)| {
            let i = members
                .iter()
                .position(|m| m == pk)
                .ok_or(SignatureError::BadMultisig("signer is not a member"))?;
            Ok((i as u8, *sig))
        })
        .collect::<Result<Vec<_>, SignatureError>>()?;
    indexed.sort_unstable_by_key(|(i, _)| *i);
    let mut out = vec![threshold, members.len() as u8];
    members.iter().for_each(|m| out.extend_from_slice(m));
    for (i, sig) in indexed {
        out.push(i);
        out.extend_from_slice(&sig);
    }
    Ok(hex::encode(out))
}

/// Exactly `threshold` signatures, indices strictly ascending: a relayer
/// can't pad or reorder a witness into a second valid encoding (and a second
/// action id) without a member's key.
fn verify_multisig(policy: &[u8], witness: &[u8], message: &[u8]) -> Result<(), SignatureError> {
    let [threshold, n, rest @ ..] = witness else {
        return Err(SignatureError::BadMultisig("witness too short"));
    };
    let (t, n) = (usize::from(*threshold), usize::from(*n));
    if rest.len() != 32 * n + 65 * t {
        return Err(SignatureError::BadMultisig(
            "witness length does not match its policy",
        ));
    }
    let (member_bytes, sigs) = rest.split_at(32 * n);
    let members: Vec<[u8; 32]> = member_bytes
        .chunks_exact(32)
        .map(|c| c.try_into().expect("chunks_exact(32)"))
        .collect();
    if policy_hash(*threshold, &members)?[..] != *policy {
        return Err(SignatureError::BadMultisig(
            "policy does not match sender address",
        ));
    }
    let mut last = None;
    for entry in sigs.chunks_exact(65) {
        let i = usize::from(entry[0]);
        if i >= n || last.is_some_and(|l| i <= l) {
            return Err(SignatureError::BadMultisig(
                "signer indices must be ascending members",
            ));
        }
        last = Some(i);
        verify_one(&members[i], &entry[1..], message)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_action() -> Action<u64> {
        Action {
            sender: Address::from_pubkey_bytes(&[9u8; 32]).unwrap(),
            nonce: 1,
            signature: None,
            payload: 42,
        }
    }

    /// A padded payload blob (one trailing byte appended inside the
    /// length-prefixed payload bytes, after the canonical encoding of `P`)
    /// must be rejected, not silently accepted — see
    /// `Implementation_log_2026-09-05.md`. Accepting it would mean the
    /// decoded `Action<P>` re-encodes to different bytes than arrived on the
    /// wire, breaking `xc_poe::tx_root` and fault adjudication for any peer
    /// that pads a payload by even one byte.
    /// The all-zero pubkey is a small-order point: under cofactored
    /// verification a (R, s) pair exists that verifies for *every* message.
    /// `verify_strict` must refuse it before anyone funds `arx1qqq…`.
    #[test]
    fn small_order_sender_never_verifies() {
        let mut action = test_action();
        action.sender = Address::from_pubkey_bytes(&[0u8; 32]).unwrap();
        // Forgery: s = 0, so verification reduces to R == -[h]A. A has
        // order 4, so -[h]A is one of four points; try all four encodings.
        let mut two_a = [0xffu8; 32];
        two_a[0] = 0xec;
        two_a[31] = 0x7f;
        let mut three_a = [0u8; 32];
        three_a[31] = 0x80;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        // Which point works depends on h mod 4, i.e. on the message, so
        // sweep a few nonces: under plain `verify` one lands within a
        // handful; under `verify_strict` none ever does.
        for nonce in 0..16 {
            action.nonce = nonce;
            for r in [identity, [0u8; 32], two_a, three_a] {
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&r);
                action.signature = Some(hex::encode(sig));
                assert!(
                    action.verify_signature().is_err(),
                    "nonce {nonce} R={} must not verify",
                    hex::encode(r)
                );
            }
        }
    }

    fn member(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = key.verifying_key().to_bytes();
        (key, pk)
    }

    /// 2-of-3: any two members pass; one, a repeated one, three, a
    /// non-member, or a policy that isn't the sender's all fail.
    #[test]
    fn multisig_needs_exactly_threshold_distinct_members() {
        use ed25519_dalek::Signer;
        let keys = [member(1), member(2), member(3)];
        let pks: Vec<[u8; 32]> = keys.iter().map(|(_, pk)| *pk).collect();
        let mut action = test_action();
        action.sender = multisig_address(2, &pks).unwrap();
        // Member order is irrelevant to the address.
        let reversed: Vec<_> = pks.iter().rev().copied().collect();
        assert_eq!(multisig_address(2, &reversed).unwrap(), action.sender);

        let msg = action.signing_bytes();
        let sig = |i: usize| (keys[i].1, keys[i].0.sign(&msg).to_bytes());
        let with = |sigs: &[([u8; 32], [u8; 64])]| {
            let mut a = action.clone();
            a.signature = Some(multisig_signature(2, &pks, sigs).unwrap());
            a.verify_signature()
        };
        assert!(with(&[sig(0), sig(2)]).is_ok());
        assert!(with(&[sig(2), sig(1)]).is_ok());
        assert!(with(&[sig(0)]).is_err());
        assert!(with(&[sig(0), sig(0)]).is_err());
        assert!(with(&[sig(0), sig(1), sig(2)]).is_err());

        let (outsider, outsider_pk) = member(9);
        assert!(
            multisig_signature(
                2,
                &pks,
                &[sig(0), (outsider_pk, outsider.sign(&msg).to_bytes())]
            )
            .is_err()
        );

        // A valid 1-of-3 witness over the same members doesn't unlock the 2-of-3 address.
        action.signature = Some(multisig_signature(1, &pks, &[sig(0)]).unwrap());
        assert!(action.verify_signature().is_err());

        // A member's signature over a different nonce doesn't carry over.
        let mut replay = action.clone();
        replay.signature = Some(multisig_signature(2, &pks, &[sig(0), sig(1)]).unwrap());
        replay.nonce += 1;
        assert!(replay.verify_signature().is_err());
    }

    #[test]
    fn multisig_policy_bounds() {
        let pks: Vec<[u8; 32]> = (1..=3).map(|i| member(i).1).collect();
        assert!(multisig_address(0, &pks).is_err());
        assert!(multisig_address(4, &pks).is_err());
        assert!(multisig_address(1, &[pks[0], pks[0]]).is_err());
        let many: Vec<[u8; 32]> = (1..=17).map(|i| member(i).1).collect();
        assert!(multisig_address(1, &many).is_err());
        assert!(multisig_address(1, &many[..16]).is_ok());
    }

    #[test]
    fn trailing_bytes_inside_payload_blob_are_rejected() {
        let action = test_action();
        let mut payload_bytes =
            bincode::serde::encode_to_vec(action.payload, crate::wire_config()).unwrap();
        payload_bytes.push(0xff);
        let wire = ActionWire {
            sender: action.sender,
            nonce: action.nonce,
            signature: action.signature,
            payload: payload_bytes,
        };
        let bytes = bincode::serde::encode_to_vec(&wire, crate::wire_config()).unwrap();
        let result: Result<(Action<u64>, usize), _> =
            bincode::serde::decode_from_slice(&bytes, crate::wire_config());
        assert!(result.is_err());
    }

    /// A declared payload length far beyond `MAX_WIRE_MESSAGE_SIZE` must fail
    /// fast via the configured byte limit instead of attempting a huge
    /// allocation — the gossip path decodes `Action<P>`'s payload bytes
    /// before any signature check runs, so this must be checked before the
    /// bytes are even read, not just bounded by the message that carried it.
    #[test]
    fn oversized_declared_length_is_rejected_before_allocating() {
        let huge_len_prefix =
            bincode::serde::encode_to_vec(u64::MAX / 2, bincode::config::standard()).unwrap();
        let result: Result<(Vec<u8>, usize), _> =
            bincode::serde::decode_from_slice(&huge_len_prefix, crate::wire_config());
        assert!(result.is_err());
    }
}
