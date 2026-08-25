use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::warn;
use std::time::{SystemTime, UNIX_EPOCH};
use xc_primitives::{
    AccountEntry, Action, Address, Block, MAX_FUTURE_DRIFT_SECS, SignatureError, StakeAllocation,
    ValidatorChange, eligible_proposer, expected_proposer,
};
use xc_storage::{
    AccountUpdates, ArxiumDb, BatchWritable, BlsKeyRegistration, EvidenceMarker, OperatorUpdates,
    StakeUpdates, StorageError, ValidatorSetSnapshot,
};

/// What a single dispatched action hands back: account changes, an optional
/// validator-membership change, and any stake-allocation changes. Named
/// struct instead of a growing positional tuple — every payload variant
/// across every chain implements this contract, so a fourth effect kind
/// would otherwise mean silently reordering fields everywhere.
#[derive(Debug, Default)]
pub struct BlockUpdates {
    pub accounts: AccountUpdates,
    pub validator_change: Option<ValidatorChange>,
    pub stakes: StakeUpdates,
    /// Set only by `SubmitEquivocationEvidence` — marks the evidence
    /// processed so it can't be resubmitted for a repeat slash.
    pub evidence: Option<EvidenceMarker>,
    /// Set only by `RegisterBlsKey` — registers the sender's BLS pubkey for
    /// `arxd/finality` precommit-vote verification.
    pub bls_key: Option<BlsKeyRegistration>,
    /// Set only by `AuthorizeOperator`/`RevokeOperator`.
    pub operator: OperatorUpdates,
}

/// Resolves every stake allocation whose unbonding batch matured at or
/// before `height`, crediting masters back and clearing the allocation —
/// meant to run *before* the action-dispatch loop each block (as the `seed`
/// passed to `execute_actions`), so a same-block `Stake`/`Unstake` action
/// against a pair that just cleared sees the cleared state instead of
/// hitting "already unbonding".
pub fn resolve_matured_unbonding(db: &ArxiumDb, height: u64) -> Result<BlockUpdates, StorageError> {
    let due = db.get_allocations_with_unbonding_due(height)?;
    let (accounts, stakes) =
        circuit_staking::resolve_due_unbonding(|addr| db.get_account(addr), due)?;
    Ok(BlockUpdates {
        accounts,
        validator_change: None,
        stakes,
        evidence: None,
        bls_key: None,
        operator: OperatorUpdates::default(),
    })
}

/// Folds `changes` (in order) onto `set`, dedupes, and sorts — the same
/// deterministic shape `expected_proposer` requires. A join for an address
/// already present, or a leave for one that isn't, is a no-op rather than an
/// error here: `dispatch` is where membership preconditions (e.g. "can't
/// leave the last validator") get enforced before a `ValidatorChange` is
/// ever produced.
pub fn apply_validator_changes(mut set: Vec<Address>, changes: &[ValidatorChange]) -> Vec<Address> {
    for change in changes {
        match change {
            ValidatorChange::Join(address, _entry) => {
                if !set.contains(address) {
                    set.push(address.clone());
                }
            }
            ValidatorChange::Leave(address) => set.retain(|a| a != address),
        }
    }
    set.sort();
    set.dedup();
    set
}

#[derive(Error, Debug)]
pub enum ExecutorError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("signature check failed: {0}")]
    Signature(#[from] SignatureError),
}

/// Everything that must hold before a block received from a peer (gossip,
/// eventually sync) is allowed to extend this node's chain. Mirrors
/// `xc_mempool::validate_action`'s role for actions: the single place this
/// check lives, so a locally-produced block and a gossiped one are held to
/// the same bar.
#[derive(Debug, Error)]
pub enum AcceptBlockError {
    #[error("proposer signature invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("wrong proposer for height {height}: expected {expected:?}, got {actual:?}")]
    WrongProposer {
        height: u64,
        expected: Option<Address>,
        actual: Option<Address>,
    },
    #[error("block height {block_height} does not extend local tip {tip_height}")]
    NotNextHeight { block_height: u64, tip_height: u64 },
    #[error("parent hash mismatch: local tip is {local}, block expects {expected}")]
    ParentMismatch { local: String, expected: String },
    #[error(
        "block {height} timestamp {timestamp} does not advance past its parent's {parent_timestamp}"
    )]
    NonMonotonicTimestamp {
        height: u64,
        timestamp: u64,
        parent_timestamp: u64,
    },
    #[error(
        "block {height} timestamp {timestamp} is {drift}s ahead of local clock (max {max_drift}s)"
    )]
    TimestampTooFarAhead {
        height: u64,
        timestamp: u64,
        drift: u64,
        max_drift: u64,
    },
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("failed to execute block actions: {0}")]
    Execution(#[from] ExecutorError),
    #[error(
        "block {block_height} claimed {claimed} action(s) but only {executed} executed successfully — proposer included an invalid action"
    )]
    ActionMismatch {
        block_height: u64,
        claimed: usize,
        executed: usize,
    },
}

/// Validates a block received from a peer — proposer signature, that the
/// signer was actually the expected round-robin proposer for that height
/// (the check that makes round-robin meaningful across nodes, not just
/// within one node's own loop), and that it extends the local tip — then
/// applies it exactly like a locally-produced block would (re-running
/// `execute_actions` against local state rather than trusting the sender's
/// claimed results). Returns the stored block on success.
///
/// `sync`: false for a single gossiped block (fsync immediately — it may be
/// the only block for a while). true when replaying a page of already-
/// finalized blocks from `SyncRequest::Blocks` catch-up — skips the fsync
/// per block; the caller must call `ArxiumDb::flush_wal` once after the
/// whole page lands.
///
/// `fee_per_action`: the chain's flat per-action fee (e.g. arxd/node's
/// `ACTION_FEE`, 0 for a chain with none) — this crate doesn't know the fee
/// amount itself (that's chain-specific, charged inside `dispatch`), only
/// how many actions applied. `applied.len() * fee_per_action` is handed to
/// `circuit_staking::apply_block_reward` to split between the block
/// proposer and treasury.
pub fn accept_block<P>(
    db: &ArxiumDb,
    block: Block<P>,
    slot_duration_secs: u64,
    sync: bool,
    fee_per_action: u128,
    dispatch: impl Fn(
        &Action<P>,
        &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
        &dyn Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
        &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        &[Address],
    ) -> anyhow::Result<BlockUpdates>,
) -> Result<Block<P>, AcceptBlockError>
where
    P: Serialize + DeserializeOwned + Clone,
{
    block.verify_proposer_signature()?;

    let tip_height = db.get_tip_height()?.unwrap_or(0);
    if block.height != tip_height + 1 {
        return Err(AcceptBlockError::NotNextHeight {
            block_height: block.height,
            tip_height,
        });
    }
    let parent: Block<P> = db
        .get_block(tip_height)?
        .expect("tip block must exist if tip_height set");
    if block.parent_hash != parent.hash() {
        return Err(AcceptBlockError::ParentMismatch {
            local: parent.hash(),
            expected: block.parent_hash.clone(),
        });
    }

    // Timestamps are consensus-critical here, not just metadata: proposer
    // eligibility below is derived from `block.timestamp - parent.timestamp`,
    // so an unchecked timestamp lets a proposer choose its own eligibility.
    // Both rules are skipped for the block after genesis, whose parent
    // timestamp is a synthetic 0 rather than a real moment (see the `elapsed`
    // comment below).
    if parent.height > 0 {
        // Monotonicity. Without it, a proposer can stamp a block at or before
        // its parent and `saturating_sub` silently reports `elapsed == 0`,
        // which is always the primary's own window — a way to take a height
        // that had already rotated away.
        if block.timestamp <= parent.timestamp {
            return Err(AcceptBlockError::NonMonotonicTimestamp {
                height: block.height,
                timestamp: block.timestamp,
                parent_timestamp: parent.timestamp,
            });
        }

        // Future-drift bound. This is the one place acceptance consults the
        // local wall clock, which is a deliberate exception to the
        // "never wall-clock-at-receipt" rule `eligible_proposer` documents:
        // two nodes with different clocks can briefly disagree about a block
        // right at the boundary. That is safe here only because rejection is
        // recoverable — the node stays behind and sync re-requests the height
        // moments later — and because the alternative is unbounded: a
        // timestamp years ahead poisons every descendant's `elapsed`.
        //
        // Only *future* drift is checked. Historical blocks replayed during
        // sync have timestamps in the past and pass unconditionally, so
        // catch-up never depends on how long ago the chain produced a block.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if block.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_SECS) {
            return Err(AcceptBlockError::TimestampTooFarAhead {
                height: block.height,
                timestamp: block.timestamp,
                drift: block.timestamp.saturating_sub(now),
                max_drift: MAX_FUTURE_DRIFT_SECS,
            });
        }
    }

    // The set as of `block.height` — a change made *by* this block only
    // takes effect at `block.height + 1` (see `ValidatorSetSnapshot`), so
    // this is also the pre-block set `dispatch` should validate
    // JoinValidator/LeaveValidator preconditions against below.
    let validators = db.get_validator_set_at(block.height)?;
    // `block.timestamp - parent.timestamp`, not wall-clock-at-receipt — every
    // node (live or replaying during sync) computes the same elapsed time
    // from the same two stored timestamps, so they always agree on who was
    // eligible to stand in for a late primary.
    //
    // Genesis is the one exception: its timestamp is a synthetic constant
    // (0), not a real wall-clock moment, so `block.timestamp - 0` is really
    // just block 1's real epoch timestamp — tens of years, always capping
    // skip at max. Height 1 always uses the plain primary, no timeout.
    let elapsed = if parent.height == 0 {
        0
    } else {
        block.timestamp.saturating_sub(parent.timestamp)
    };
    let expected = eligible_proposer(&validators, block.height, elapsed, slot_duration_secs);
    if block.proposer != expected {
        return Err(AcceptBlockError::WrongProposer {
            height: block.height,
            expected,
            actual: block.proposer.clone(),
        });
    }

    // A gossiped block's `hash()` covers its full action list, computed by
    // the proposer. If any action here fails execution locally (bad
    // signature, stale nonce, whatever `dispatch` rejects), storing a
    // trimmed `actions` list would make our copy hash differently from the
    // proposer's — and every subsequent block's parent-hash check would
    // then fail on this node, forever. A proposer's block must either apply
    // exactly as claimed or be rejected outright; there's no partial credit
    // for a block the way there is for a fresh batch from the mempool.
    let claimed = block.actions.len();
    let seed = resolve_matured_unbonding(db, block.height)?;
    let (
        applied,
        mut account_updates,
        validator_changes,
        mut stake_updates,
        evidence_markers,
        bls_keys,
        operator_updates,
    ) = execute_actions(db, block.actions.clone(), &validators, seed, dispatch)?;
    if applied.len() != claimed {
        return Err(AcceptBlockError::ActionMismatch {
            block_height: block.height,
            claimed,
            executed: applied.len(),
        });
    }

    // `verify_proposer_signature` above already guarantees `Some` — an
    // unsigned block never reaches this point.
    let proposer = block.proposer.as_ref().expect("signed block always has a proposer");
    let fees_collected = applied.len() as u128 * fee_per_action;
    let account_lookup = |addr: &Address| match account_updates.0.get(addr) {
        Some(entry) => Ok(Some(entry.clone())),
        None => db.get_account(addr),
    };
    let reward_updates = circuit_staking::apply_block_reward(account_lookup, proposer, fees_collected)?;
    account_updates.0.extend(reward_updates.0);

    // §7.3 downtime slash: if the height's primary round-robin proposer
    // wasn't who actually produced it, they missed their slot — burn a
    // small automatic slash. No evidence needed, every node agrees from
    // the same stored block.
    if let Some(primary) = expected_proposer(&validators, block.height) {
        let account_lookup = |addr: &Address| match account_updates.0.get(addr) {
            Some(entry) => Ok(Some(entry.clone())),
            None => db.get_account(addr),
        };
        let allocation_lookup = |m: &Address, v: &Address| {
            match stake_updates.allocations.get(&(m.clone(), v.clone())) {
                Some(a) => Ok(a.clone()),
                None => db.get_stake_allocation(m, v),
            }
        };
        let masters_lookup = |v: &Address| match stake_updates.validator_index.get(v) {
            Some(m) => Ok(m.clone()),
            None => db.get_stakes_by_validator(v),
        };
        let (downtime_accounts, downtime_stakes) = circuit_staking::apply_downtime_slash(
            account_lookup,
            allocation_lookup,
            masters_lookup,
            &primary,
            proposer,
            block.height,
        )?;
        account_updates.0.extend(downtime_accounts.0);
        stake_updates.allocations.extend(downtime_stakes.allocations);
        stake_updates.validator_index.extend(downtime_stakes.validator_index);
    }

    let new_validator_set = if validator_changes.is_empty() {
        None
    } else {
        Some(ValidatorSetSnapshot {
            effective_height: block.height + 1,
            validators: apply_validator_changes(validators, &validator_changes),
        })
    };

    let mut writables: Vec<&dyn BatchWritable> = vec![&account_updates, &stake_updates];
    if let Some(snapshot) = &new_validator_set {
        writables.push(snapshot);
    }
    for marker in &evidence_markers {
        writables.push(marker);
    }
    for registration in &bls_keys {
        writables.push(registration);
    }
    writables.push(&operator_updates);
    writables.push(&block);
    if sync {
        db.write_batches_unsynced(&writables)?;
    } else {
        db.write_batches(&writables)?;
    }
    Ok(block)
}

/// Applies each action to current state, in order, buffering every success
/// in memory (an overlay on top of the DB) so later actions in the same
/// batch see its effect (e.g. two transfers from the same sender at
/// consecutive nonces) without touching the DB at all. An action that fails
/// on its own (bad signature, or whatever `dispatch` rejects) is skipped and
/// logged rather than aborting the batch — one bad action must not block
/// valid actions from other senders. Returns the actions that were actually
/// applied, in order, plus the resulting account changes — unwritten. The
/// caller is responsible for committing these together with the block
/// record in one atomic write, so a crash can never leave block bookkeeping
/// and account state disagreeing.
///
/// `dispatch` is the chain-specific payload → circuit mapping — this
/// function only owns the generic loop mechanics (signature check, overlay
/// chaining, buffer-and-skip-on-error), not what any given payload variant
/// means. `P` is the chain's action payload type.
pub fn execute_actions<P>(
    db: &ArxiumDb,
    actions: Vec<Action<P>>,
    validators: &[Address],
    seed: BlockUpdates,
    dispatch: impl Fn(
        &Action<P>,
        &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
        &dyn Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
        &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        &[Address],
    ) -> anyhow::Result<BlockUpdates>,
) -> Result<
    (
        Vec<Action<P>>,
        AccountUpdates,
        Vec<ValidatorChange>,
        StakeUpdates,
        Vec<EvidenceMarker>,
        Vec<BlsKeyRegistration>,
        OperatorUpdates,
    ),
    ExecutorError,
>
where
    P: serde::Serialize,
{
    let mut applied = Vec::with_capacity(actions.len());
    // Seeded from e.g. matured-unbonding resolution, run by the caller
    // before this loop — so a same-block `Stake` action sees a just-cleared
    // `unbonding` slot instead of hitting "already unbonding".
    let mut overlay = seed.accounts.0;
    let mut validator_changes: Vec<ValidatorChange> = seed.validator_change.into_iter().collect();
    let mut stake_overlay = seed.stakes.allocations;
    let mut validator_index_overlay = seed.stakes.validator_index;
    let mut evidence_markers: Vec<EvidenceMarker> = seed.evidence.into_iter().collect();
    let mut bls_keys: Vec<BlsKeyRegistration> = seed.bls_key.into_iter().collect();
    let mut operator_overlay = seed.operator.authorization;
    let mut operator_index_overlay = seed.operator.operator_index;

    for action in actions {
        if let Err(err) = action.verify_signature() {
            warn!("dropping action from {}: {err}", action.sender);
            continue;
        }

        let lookup = |addr: &Address| match overlay.get(addr) {
            Some(entry) => Ok(Some(entry).cloned()),
            None => db.get_account(addr),
        };
        let stake_lookup = |master: &Address, validator: &Address| match stake_overlay
            .get(&(master.clone(), validator.clone()))
        {
            Some(entry) => Ok(Clone::clone(entry)),
            None => db.get_stake_allocation(master, validator),
        };
        let validator_masters_lookup =
            |validator: &Address| match validator_index_overlay.get(validator) {
                Some(masters) => Ok(Clone::clone(masters)),
                None => db.get_stakes_by_validator(validator),
            };
        let operator_lookup = |validator: &Address| match operator_overlay.get(validator) {
            Some(operator) => Ok(Clone::clone(operator)),
            None => db.get_operator(validator),
        };
        let operator_validators_lookup =
            |operator: &Address| match operator_index_overlay.get(operator) {
                Some(validators) => Ok(Clone::clone(validators)),
                None => db.get_validators_for_operator(operator),
            };

        match dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &operator_lookup,
            &operator_validators_lookup,
            validators,
        ) {
            Ok(updates) => {
                overlay.extend(updates.accounts.0);
                validator_changes.extend(updates.validator_change);
                stake_overlay.extend(updates.stakes.allocations);
                validator_index_overlay.extend(updates.stakes.validator_index);
                evidence_markers.extend(updates.evidence);
                bls_keys.extend(updates.bls_key);
                operator_overlay.extend(updates.operator.authorization);
                operator_index_overlay.extend(updates.operator.operator_index);
                applied.push(action);
            }
            Err(err) => warn!("dropping action from {}: {err}", action.sender),
        }
    }

    Ok((
        applied,
        AccountUpdates(overlay),
        validator_changes,
        StakeUpdates {
            allocations: stake_overlay,
            validator_index: validator_index_overlay,
        },
        evidence_markers,
        bls_keys,
        OperatorUpdates {
            authorization: operator_overlay,
            operator_index: operator_index_overlay,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit_account::apply_transfer;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum TestPayload {
        Transfer { to: Address, amount: u128 },
        Join,
        Stake { validator: Address, amount: u128 },
    }

    fn dispatch(
        action: &Action<TestPayload>,
        lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
        stake_lookup: &dyn Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
        validator_masters_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        _operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        _operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        _validators: &[Address],
    ) -> anyhow::Result<BlockUpdates> {
        match &action.payload {
            TestPayload::Stake { validator, amount } => {
                let (accounts, stakes) = circuit_staking::apply_stake(
                    lookup,
                    stake_lookup,
                    validator_masters_lookup,
                    &action.sender,
                    action.nonce,
                    validator,
                    *amount,
                    0,
                )?;
                Ok(BlockUpdates {
                    accounts,
                    stakes,
                    ..Default::default()
                })
            }
            TestPayload::Transfer { to, amount } => Ok(BlockUpdates {
                accounts: apply_transfer(lookup, &action.sender, action.nonce, to, *amount)?,
                ..Default::default()
            }),
            TestPayload::Join => Ok(BlockUpdates {
                validator_change: Some(ValidatorChange::Join(
                    action.sender.clone(),
                    xc_primitives::ValidatorEntry { stake: 0 },
                )),
                ..Default::default()
            }),
        }
    }

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-executor-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    // ponytail: nanos alone collide often enough under parallel test
    // execution to hit RocksDB's single-writer LOCK (seen in practice, not
    // hypothetical) — the atomic counter guarantees uniqueness even when two
    // threads land on the same tick.
    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn signed_transfer(
        key: &SigningKey,
        sender: &Address,
        nonce: u64,
        to: &Address,
        amount: u128,
    ) -> Action<TestPayload> {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: TestPayload::Transfer {
                to: to.clone(),
                amount,
            },
        };
        let signature = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(signature.to_bytes()));
        action
    }

    fn signed_join(key: &SigningKey, sender: &Address, nonce: u64) -> Action<TestPayload> {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: TestPayload::Join,
        };
        let signature = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(signature.to_bytes()));
        action
    }

    #[test]
    fn validator_join_takes_effect_one_block_later_not_the_block_that_added_it() {
        let db = temp_db();
        let alice_key = SigningKey::from_bytes(&[7u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let bob_key = SigningKey::from_bytes(&[8u8; 32]);
        let bob = Address::from_pubkey_bytes(bob_key.verifying_key().as_bytes()).unwrap();

        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![alice.clone()],
        })
        .unwrap();
        let genesis: Block<TestPayload> = Block::genesis(0);
        db.write_batches(&[&AccountUpdates(HashMap::new()), &genesis])
            .unwrap();

        let mut block1 = Block {
            height: 1,
            parent_hash: genesis.hash(),
            timestamp: 1,
            actions: vec![signed_join(&bob_key, &bob, 0)],
            proposer: None,
            signature: None,
        };
        block1.sign(alice.clone(), &alice_key);

        let accepted = accept_block(&db, block1, 4, false, 0, dispatch).unwrap();
        assert_eq!(accepted.actions.len(), 1, "join action must be applied");

        // Block 1 itself is still decided by the pre-join set.
        assert_eq!(db.get_validator_set_at(1).unwrap(), vec![alice.clone()]);
        // Bob only becomes a validator starting block 2.
        let mut expected = vec![alice, bob];
        expected.sort();
        assert_eq!(db.get_validator_set_at(2).unwrap(), expected);
    }

    #[test]
    fn same_block_actions_chain_and_commit_atomically() {
        let db = temp_db();
        let alice_key = SigningKey::from_bytes(&[3u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let bob = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();

        db.write_batch(&AccountUpdates(HashMap::from([(
            alice.clone(),
            AccountEntry {
                balance: 100,
                nonce: 0,
                identity_hash: None,
                zk_identity_verified: false,
            },
        )])))
        .unwrap();

        // Two consecutive-nonce transfers from the same sender in one
        // batch: the second can only validate if it sees the first's
        // effect on alice's nonce/balance, which the DB alone won't show
        // until the whole batch is committed — proves the overlay works.
        let actions = vec![
            signed_transfer(&alice_key, &alice, 0, &bob, 40),
            signed_transfer(&alice_key, &alice, 1, &bob, 10),
        ];

        let (
            applied,
            updates,
            validator_changes,
            _stake_updates,
            _evidence_markers,
            _bls_keys,
            _operator_updates,
        ) = execute_actions(&db, actions, &[], BlockUpdates::default(), dispatch).unwrap();
        assert!(validator_changes.is_empty());
        assert_eq!(
            applied.len(),
            2,
            "both consecutive-nonce actions should apply"
        );

        // Not yet written — execute_actions only buffers; the caller commits.
        assert!(db.get_account(&bob).unwrap().is_none());

        db.write_batch(&updates).unwrap();

        let alice_after = db.get_account(&alice).unwrap().unwrap();
        assert_eq!(alice_after.balance, 50);
        assert_eq!(alice_after.nonce, 2);

        let bob_after = db.get_account(&bob).unwrap().unwrap();
        assert_eq!(bob_after.balance, 50);
    }

    fn signed_stake(
        key: &SigningKey,
        sender: &Address,
        nonce: u64,
        validator: &Address,
        amount: u128,
    ) -> Action<TestPayload> {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: TestPayload::Stake {
                validator: validator.clone(),
                amount,
            },
        };
        let signature = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(signature.to_bytes()));
        action
    }

    #[test]
    fn stake_allocation_and_block_height_commit_atomically() {
        let db = temp_db();
        let alice_key = SigningKey::from_bytes(&[11u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let validator = Address::from_pubkey_bytes(&[12u8; 32]).unwrap();

        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![alice.clone()],
        })
        .unwrap();
        let genesis: Block<TestPayload> = Block::genesis(0);
        db.write_batches(&[
            &AccountUpdates(HashMap::from([(
                alice.clone(),
                AccountEntry {
                    balance: 1000,
                    nonce: 0,
                    identity_hash: None,
                    zk_identity_verified: false,
                },
            )])),
            &genesis,
        ])
        .unwrap();

        let mut block1 = Block {
            height: 1,
            parent_hash: genesis.hash(),
            timestamp: 1,
            actions: vec![signed_stake(&alice_key, &alice, 0, &validator, 400)],
            proposer: None,
            signature: None,
        };
        block1.sign(alice.clone(), &alice_key);

        let accepted = accept_block(&db, block1, 4, false, 0, dispatch).unwrap();
        assert_eq!(accepted.actions.len(), 1, "stake action must be applied");

        // Never disagree: if the block landed, the stake it caused landed
        // with it — both come out of the same `write_batches` call.
        assert_eq!(db.get_tip_height().unwrap(), Some(1));
        let allocation = db
            .get_stake_allocation(&alice, &validator)
            .unwrap()
            .unwrap();
        assert_eq!(allocation.active_amount, 400);
        assert_eq!(db.get_account(&alice).unwrap().unwrap().balance, 600);
    }

    #[test]
    fn unbonding_resolves_before_same_block_actions_so_restaking_succeeds() {
        let db = temp_db();
        let alice_key = SigningKey::from_bytes(&[13u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let validator = Address::from_pubkey_bytes(&[14u8; 32]).unwrap();

        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![alice.clone()],
        })
        .unwrap();
        let genesis: Block<TestPayload> = Block::genesis(0);
        db.write_batches(&[
            &AccountUpdates(HashMap::from([(
                alice.clone(),
                AccountEntry {
                    balance: 1000,
                    nonce: 0,
                    identity_hash: None,
                    zk_identity_verified: false,
                },
            )])),
            &genesis,
        ])
        .unwrap();

        // Seed an allocation that's already fully unbonding, maturing at
        // exactly block 1 — set up directly rather than waiting out
        // `UNBONDING_BLOCKS` real blocks.
        let mut stake_updates = StakeUpdates::default();
        stake_updates.allocations.insert(
            (alice.clone(), validator.clone()),
            Some(StakeAllocation {
                master: alice.clone(),
                validator: validator.clone(),
                active_amount: 0,
                unbonding: Some(xc_primitives::Unbonding {
                    amount: 300,
                    unlock_at_height: 1,
                }),
                created_at: 0,
                updated_at: 0,
            }),
        );
        stake_updates
            .validator_index
            .insert(validator.clone(), vec![alice.clone()]);
        db.write_batch(&stake_updates).unwrap();
        // Sub-account must actually hold the unbonding amount — it's what
        // `resolve_due_unbonding` debits back to alice.
        let sub_account = circuit_staking::stake_subaccount(&validator);
        db.write_batch(&AccountUpdates(HashMap::from([(
            sub_account,
            AccountEntry {
                balance: 300,
                nonce: 0,
                identity_hash: None,
                zk_identity_verified: false,
            },
        )])))
        .unwrap();

        let mut block1 = Block {
            height: 1,
            parent_hash: genesis.hash(),
            timestamp: 1,
            // Without the unbonding-resolves-first ordering, this would hit
            // `AlreadyUnbonding` since the allocation above is still mid-unbond.
            actions: vec![signed_stake(&alice_key, &alice, 0, &validator, 200)],
            proposer: None,
            signature: None,
        };
        block1.sign(alice.clone(), &alice_key);

        let accepted = accept_block(&db, block1, 4, false, 0, dispatch).unwrap();
        assert_eq!(
            accepted.actions.len(),
            1,
            "restaking in the same block the unbonding matures must succeed"
        );

        // The matured 300 landed back on alice's balance, then 200 of it was
        // immediately restaked.
        assert_eq!(
            db.get_account(&alice).unwrap().unwrap().balance,
            1000 + 300 - 200
        );
        let allocation = db
            .get_stake_allocation(&alice, &validator)
            .unwrap()
            .unwrap();
        assert_eq!(allocation.active_amount, 200);
        assert!(allocation.unbonding.is_none());
    }

    /// Builds a single-validator chain up to height 1 and returns everything
    /// needed to propose height 2. A one-validator set means `eligible_proposer`
    /// always returns that validator, so these tests isolate the timestamp
    /// rules from the proposer rule.
    fn chain_at_height_one(
        block1_timestamp: u64,
    ) -> (ArxiumDb, SigningKey, Address, Block<TestPayload>) {
        let db = temp_db();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();

        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![addr.clone()],
        })
        .unwrap();
        let genesis: Block<TestPayload> = Block::genesis(0);
        db.write_batches(&[&AccountUpdates(HashMap::new()), &genesis])
            .unwrap();

        let mut block1 = Block {
            height: 1,
            parent_hash: genesis.hash(),
            timestamp: block1_timestamp,
            actions: vec![],
            proposer: None,
            signature: None,
        };
        block1.sign(addr.clone(), &key);
        let block1 = accept_block(&db, block1, 4, false, 0, dispatch).unwrap();
        (db, key, addr, block1)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed_block_at(
        key: &SigningKey,
        addr: &Address,
        parent: &Block<TestPayload>,
        timestamp: u64,
    ) -> Block<TestPayload> {
        let mut block = Block {
            height: parent.height + 1,
            parent_hash: parent.hash(),
            timestamp,
            actions: vec![],
            proposer: None,
            signature: None,
        };
        block.sign(addr.clone(), key);
        block
    }

    /// A proposer must not be able to stamp a block at or before its parent.
    /// `elapsed` is computed with `saturating_sub`, so a backwards timestamp
    /// silently reads as `elapsed == 0` — the primary's own window — which is
    /// a way to claim a height that had already rotated to someone else.
    #[test]
    fn rejects_a_timestamp_that_does_not_advance_past_the_parent() {
        let base = now_secs() - 10;
        let (db, key, addr, block1) = chain_at_height_one(base);

        for stamp in [base, base - 1, 0] {
            let block2 = signed_block_at(&key, &addr, &block1, stamp);
            let err = accept_block(&db, block2, 4, false, 0, dispatch).unwrap_err();
            assert!(
                matches!(err, AcceptBlockError::NonMonotonicTimestamp { .. }),
                "timestamp {stamp} against parent {base} should be rejected, got {err:?}",
            );
        }

        // One second later is the minimum acceptable step, and it works.
        let block2 = signed_block_at(&key, &addr, &block1, base + 1);
        assert!(accept_block(&db, block2, 4, false, 0, dispatch).is_ok());
    }

    /// Proposer eligibility is derived from block timestamps, so an unbounded
    /// future timestamp lets a proposer buy itself an arbitrary round *and*
    /// poisons every descendant's `elapsed` for as long as the forgery is
    /// ahead. Bounded by `MAX_FUTURE_DRIFT_SECS`.
    #[test]
    fn rejects_a_timestamp_too_far_in_the_future() {
        let (db, key, addr, block1) = chain_at_height_one(now_secs() - 10);

        // A year ahead: the shape that used to stall the rotation indefinitely.
        let block2 = signed_block_at(&key, &addr, &block1, now_secs() + 31_536_000);
        let err = accept_block(&db, block2, 4, false, 0, dispatch).unwrap_err();
        assert!(
            matches!(err, AcceptBlockError::TimestampTooFarAhead { .. }),
            "got {err:?}",
        );

        // Just past the bound is still rejected.
        let block2 = signed_block_at(&key, &addr, &block1, now_secs() + MAX_FUTURE_DRIFT_SECS + 5);
        assert!(matches!(
            accept_block(&db, block2, 4, false, 0, dispatch).unwrap_err(),
            AcceptBlockError::TimestampTooFarAhead { .. }
        ));

        // Modest skew inside the bound is accepted — an honest node with a
        // slightly fast clock must not have its blocks refused.
        let block2 = signed_block_at(&key, &addr, &block1, now_secs() + 2);
        assert!(accept_block(&db, block2, 4, false, 0, dispatch).is_ok());
    }

    /// Only *future* drift is bounded. Blocks replayed during sync are old by
    /// definition, and catch-up must never depend on how long ago the chain
    /// produced them — a chain idle for a year still has to be syncable.
    #[test]
    fn old_blocks_replayed_during_sync_are_not_rejected_for_drift() {
        let long_ago = now_secs() - 31_536_000;
        let (db, key, addr, block1) = chain_at_height_one(long_ago);

        let block2 = signed_block_at(&key, &addr, &block1, long_ago + 4);
        assert!(
            accept_block(&db, block2, 4, true, 0, dispatch).is_ok(),
            "a year-old block must still replay during sync",
        );
    }

    /// The block after genesis is exempt: genesis carries a synthetic
    /// timestamp of 0 rather than a real moment, so measuring block 1 against
    /// it is meaningless. Guards the exemption against being dropped by
    /// someone tightening the rule later — it would make every chain
    /// unstartable.
    #[test]
    fn the_block_after_genesis_is_exempt_from_the_timestamp_rules() {
        let (_db, _key, _addr, block1) = chain_at_height_one(now_secs());
        assert_eq!(block1.height, 1, "block 1 must be accepted over synthetic genesis");
    }
}
