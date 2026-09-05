// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::Address;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    /// over this action's (sender, nonce, payload).
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        let sig_hex = self.signature.as_deref().ok_or(SignatureError::Missing)?;
        let sig_bytes = hex::decode(sig_hex).map_err(|_| SignatureError::InvalidHex)?;
        let sig_bytes: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::WrongLength(sig_bytes.len()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let pubkey_bytes = self.sender.pubkey_bytes()?;
        let pubkey_bytes: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::WrongLength(pubkey_bytes.len()))?;
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SignatureError::Invalid)?;

        verifying_key
            .verify(&self.signing_bytes(), &signature)
            .map_err(|_| SignatureError::Invalid)
    }
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
    #[test]
    fn trailing_bytes_inside_payload_blob_are_rejected() {
        let action = test_action();
        let mut payload_bytes =
            bincode::serde::encode_to_vec(&action.payload, crate::wire_config()).unwrap();
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
            bincode::serde::encode_to_vec(&(u64::MAX / 2), bincode::config::standard()).unwrap();
        let result: Result<(Vec<u8>, usize), _> =
            bincode::serde::decode_from_slice(&huge_len_prefix, crate::wire_config());
        assert!(result.is_err());
    }
}
