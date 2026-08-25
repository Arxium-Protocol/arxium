// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::Address;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// `P` is the chain-specific action payload (e.g. CoreChain's `ActionPayload`
/// or a spoke chain's own enum) — `Action` itself only knows about the
/// envelope: who sent it, at what nonce, signed how.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action<P> {
    pub sender: Address,
    pub nonce: u64,
    pub signature: Option<String>,
    pub payload: P,
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
        bincode::serde::encode_to_vec(&payload, bincode::config::standard())
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
