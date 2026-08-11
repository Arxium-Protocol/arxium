use std::collections::{HashSet, VecDeque};

use serde::Serialize;
use thiserror::Error;
use xc_primitives::{Action, Address, SignatureError};
use xc_storage::{ArxiumDb, StorageError};

// ponytail: fixed cap sized for a devnet; make configurable if throughput ever
// becomes a real constraint.
const MAX_PENDING: usize = 10_000;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("mempool is full")]
    Full,
    #[error("duplicate action for {sender} at nonce {nonce}")]
    Duplicate { sender: Address, nonce: u64 },
}

/// Everything an action must pass before it's allowed anywhere near the
/// mempool, regardless of how it arrived (RPC submission, gossip from a
/// peer). Neither entry point is more trusted than the other, so both must
/// run this exact check instead of keeping their own copy.
#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("bad signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("stale nonce for {sender}: action has {action_nonce}, current on-chain nonce is {current_nonce}")]
    StaleNonce {
        sender: Address,
        action_nonce: u64,
        current_nonce: u64,
    },
    #[error("failed to look up account for nonce check: {0}")]
    Storage(#[from] StorageError),
}

/// Validates what can be checked without executing the action: signature,
/// and that its nonce isn't already stale against on-chain state. Not a full
/// re-check of `execute_actions` — balance can still change before this
/// action's turn in a block, so insufficient-balance is still only caught at
/// production time. Rejecting a bad signature or a replayed/stale nonce here
/// means garbage never occupies a mempool slot waiting to be dropped later.
pub fn validate_action<P: Serialize>(
    db: &ArxiumDb,
    action: &Action<P>,
) -> Result<(), AdmissionError> {
    action.verify_signature()?;

    let current_nonce = db
        .get_account(&action.sender)?
        .map(|entry| entry.nonce)
        .unwrap_or(0);
    if action.nonce < current_nonce {
        return Err(AdmissionError::StaleNonce {
            sender: action.sender.clone(),
            action_nonce: action.nonce,
            current_nonce,
        });
    }

    Ok(())
}

pub struct Mempool<P> {
    pending: VecDeque<Action<P>>,
    // Tracks (sender, nonce) pairs currently queued, so a resubmitted or
    // spammed action doesn't grow the queue unboundedly — only one action
    // per sender/nonce can ever land in a block anyway.
    seen: HashSet<(Address, u64)>,
}

impl<P> Default for Mempool<P> {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            seen: HashSet::new(),
        }
    }
}

impl<P> Mempool<P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, action: Action<P>) -> Result<(), MempoolError> {
        if self.pending.len() >= MAX_PENDING {
            return Err(MempoolError::Full);
        }

        let key = (action.sender.clone(), action.nonce);
        if !self.seen.insert(key) {
            return Err(MempoolError::Duplicate {
                sender: action.sender,
                nonce: action.nonce,
            });
        }

        self.pending.push_back(action);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    // ponytail: linear scan, fine at MAX_PENDING scale; index by signature if this gets hot.
    pub fn contains_signature(&self, signature: &str) -> bool {
        self.pending
            .iter()
            .any(|action| action.signature.as_deref() == Some(signature))
    }

    pub fn drain_pending(&mut self, max: usize) -> Vec<Action<P>> {
        let n = max.min(self.pending.len());
        self.pending
            .drain(..n)
            .inspect(|action| {
                self.seen.remove(&(action.sender.clone(), action.nonce));
            })
            .collect()
    }
}
