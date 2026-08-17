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

    /// Drops any queued action for `sender` whose nonce is now stale
    /// against `current_nonce` — e.g. because some *other* block (gossiped
    /// or synced, not drained from this queue) already consumed it. Without
    /// this, a stale entry sits in the queue until this node's own turn to
    /// propose, gets silently dropped by `execute_actions` at that point,
    /// and produces exactly the same claimed/executed block mismatch a
    /// peer re-executing it would reject.
    pub fn purge_stale(&mut self, sender: &Address, current_nonce: u64) {
        let seen = &mut self.seen;
        self.pending.retain(|action| {
            if &action.sender == sender && action.nonce < current_nonce {
                seen.remove(&(action.sender.clone(), action.nonce));
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    fn action(sender: Address, nonce: u64) -> Action<()> {
        Action {
            sender,
            nonce,
            signature: Some(format!("sig-{nonce}")),
            payload: (),
        }
    }

    #[test]
    fn purge_stale_drops_only_the_now_consumed_sender_nonce() {
        let mut mempool = Mempool::new();
        let a = addr(1);
        let b = addr(2);
        mempool.push(action(a.clone(), 1)).unwrap();
        mempool.push(action(a.clone(), 2)).unwrap();
        mempool.push(action(b.clone(), 1)).unwrap();

        // Some other block already advanced `a`'s on-chain nonce to 2 —
        // nonce 1 is now stale, nonce 2 still pending, `b` untouched.
        mempool.purge_stale(&a, 2);

        assert_eq!(mempool.len(), 2);
        let drained = mempool.drain_pending(10);
        assert_eq!(
            drained
                .iter()
                .map(|act| (act.sender.clone(), act.nonce))
                .collect::<Vec<_>>(),
            vec![(a, 2), (b, 1)]
        );

        // The purged (a, 1) slot is free again, not stuck in `seen`.
        let mut mempool2 = Mempool::new();
        mempool2.push(action(addr(1), 1)).unwrap();
        mempool2.purge_stale(&addr(1), 2);
        assert!(mempool2.push(action(addr(1), 1)).is_ok());
    }
}
