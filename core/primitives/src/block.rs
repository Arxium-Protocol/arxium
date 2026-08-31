// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::action::{Action, SignatureError};
use crate::address::Address;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `P` is the chain-specific action payload — see `Action<P>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block<P> {
    pub height: u64,
    pub parent_hash: String,
    pub timestamp: u64,
    pub actions: Vec<Action<P>>,
    /// Binary Merkle root (RFC 6962 shape) over `actions` — see
    /// `xc_poe::tx_root`, which is what computes it. Signed in place of
    /// `actions` itself (see `BlockSigningPayload`), so the signing payload
    /// never has to know `P`. A signature over `tx_root` alone only means
    /// something if the two are kept in lockstep: whoever accepts a block
    /// must independently recompute `tx_root` from `actions` and reject a
    /// mismatch (`xc_executor::accept_block` does), or `actions` could be
    /// swapped out after signing without invalidating the signature.
    pub tx_root: [u8; 32],
    /// Validator that produced this block. `None` for the (trusted, unsigned)
    /// genesis block, and for blocks produced by a non-validator solo node.
    pub proposer: Option<Address>,
    pub signature: Option<String>,
    /// Root of the full account/validator/stake state *after* this block's
    /// actions apply — see `xc_storage::ArxiumDb::compute_state_root`. Lets
    /// a node verify a full state snapshot against what the chain actually
    /// finalized, instead of trusting the source.
    pub state_root: String,
}

/// What actually gets signed: everything but the signature itself (it can't
/// sign itself). Mirrors `Action`'s `SigningPayload`.
///
/// Commits to `tx_root`, not `actions` — deliberately. `actions: &[Action<P>]`
/// used to be signed directly, which made the signing payload (and this
/// struct) generic over `P`. That meant a verifier had to know a chain's
/// payload type just to check whether two blocks the same proposer signed
/// were equivocation or not, and — worse — made the signed bytes opaque:
/// nothing about them said whether two blocks were at the same height, since
/// that required decoding `P` to find out. `tx_root` is a plain `[u8; 32]`,
/// so every field here is `P`-free, and a chain-agnostic verifier can read
/// `height` straight off it without decoding anything.
#[derive(Serialize)]
struct BlockSigningPayload<'a> {
    height: u64,
    parent_hash: &'a str,
    timestamp: u64,
    tx_root: &'a [u8; 32],
    proposer: &'a Address,
    state_root: &'a str,
}

impl<P: Serialize> Block<P> {
    pub fn genesis(timestamp: u64) -> Self {
        Self {
            height: 0,
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            timestamp,
            actions: Vec::new(),
            // Matches `xc_poe::tx_root(&[])` — empty action list hashes to
            // the zero root.
            tx_root: [0u8; 32],
            proposer: None,
            signature: None,
            state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    /// Deterministic hash of this block's content
    pub fn hash(&self) -> String {
        let config = bincode::config::standard();
        let bytes =
            bincode::serde::encode_to_vec(self, config).expect("block encoding should never fail");
        let digest = Sha256::digest(&bytes);
        format!("0x{}", hex::encode(digest))
    }

    /// Deterministic bytes a valid proposer signature must cover — exposed
    /// (not just used internally by `sign`/`verify_proposer_signature`) so
    /// evidence tooling can commit to what was actually signed without
    /// needing to decode `P`.
    pub fn signing_bytes(&self, proposer: &Address) -> Vec<u8> {
        let payload = BlockSigningPayload {
            height: self.height,
            parent_hash: &self.parent_hash,
            timestamp: self.timestamp,
            tx_root: &self.tx_root,
            proposer,
            state_root: &self.state_root,
        };
        bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .expect("signing payload encoding should never fail")
    }

    /// Sets `proposer` from `key` and signs the block's content.
    pub fn sign(&mut self, proposer: Address, key: &SigningKey) {
        let bytes = self.signing_bytes(&proposer);
        let signature = key.sign(&bytes);
        self.signature = Some(hex::encode(signature.to_bytes()));
        self.proposer = Some(proposer);
    }

    /// Verifies `signature` was produced by the private key behind `proposer`,
    /// over this block's (height, parent_hash, timestamp, tx_root, proposer,
    /// state_root). Proves nothing about `actions` on its own — a caller
    /// that trusts `actions` off a validly-signed block without separately
    /// checking `tx_root` against them is trusting an unverified field; see
    /// `xc_executor::accept_block`.
    pub fn verify_proposer_signature(&self) -> Result<(), SignatureError> {
        let proposer = self.proposer.as_ref().ok_or(SignatureError::Missing)?;
        let sig_hex = self.signature.as_deref().ok_or(SignatureError::Missing)?;
        let sig_bytes = hex::decode(sig_hex).map_err(|_| SignatureError::InvalidHex)?;
        let sig_bytes: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::WrongLength(sig_bytes.len()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let pubkey_bytes = proposer.pubkey_bytes()?;
        let pubkey_bytes: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::WrongLength(pubkey_bytes.len()))?;
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SignatureError::Invalid)?;

        verifying_key
            .verify(&self.signing_bytes(proposer), &signature)
            .map_err(|_| SignatureError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(1234);
        block.height = 5;
        block.sign(addr, &key);

        assert!(block.verify_proposer_signature().is_ok());
    }

    #[test]
    fn tampered_block_fails_verification() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(1234);
        block.sign(addr, &key);

        block.timestamp += 1;
        assert!(block.verify_proposer_signature().is_err());
    }

    /// `tx_root` is part of the signed header, so changing it after signing
    /// (e.g. to claim a different action list without re-signing) must
    /// invalidate the signature — same guarantee `timestamp` etc. get above.
    /// This is the only thing `verify_proposer_signature` can prove about
    /// `actions` by itself; whether `tx_root` actually matches `actions` is
    /// a separate check owned by the caller (`xc_executor::accept_block`).
    #[test]
    fn tampered_tx_root_fails_verification() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: Block<()> = Block::genesis(1234);
        block.sign(addr, &key);

        block.tx_root = [0xffu8; 32];
        assert!(block.verify_proposer_signature().is_err());
    }

    #[test]
    fn unsigned_block_fails_verification() {
        let block: Block<()> = Block::genesis(1234);
        assert!(matches!(
            block.verify_proposer_signature(),
            Err(SignatureError::Missing)
        ));
    }
}
