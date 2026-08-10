use std::collections::{HashSet, VecDeque};

use thiserror::Error;
use xc_primitives::{Action, Address};

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

#[derive(Default)]
pub struct Mempool {
    pending: VecDeque<Action>,
    // Tracks (sender, nonce) pairs currently queued, so a resubmitted or
    // spammed action doesn't grow the queue unboundedly — only one action
    // per sender/nonce can ever land in a block anyway.
    seen: HashSet<(Address, u64)>,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, action: Action) -> Result<(), MempoolError> {
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

    pub fn drain_pending(&mut self, max: usize) -> Vec<Action> {
        let n = max.min(self.pending.len());
        self.pending
            .drain(..n)
            .inspect(|action| {
                self.seen.remove(&(action.sender.clone(), action.nonce));
            })
            .collect()
    }
}
