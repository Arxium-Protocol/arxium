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
#[derive(Serialize)]
struct BlockSigningPayload<'a, P> {
    height: u64,
    parent_hash: &'a str,
    timestamp: u64,
    actions: &'a [Action<P>],
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
            actions: &self.actions,
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
    /// over this block's (height, parent_hash, timestamp, actions, proposer).
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

    #[test]
    fn unsigned_block_fails_verification() {
        let block: Block<()> = Block::genesis(1234);
        assert!(matches!(
            block.verify_proposer_signature(),
            Err(SignatureError::Missing)
        ));
    }
}
