// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use thiserror::Error;
use xc_primitives::{AccountEntry, Address, StakeAllocation, Unbonding};
use xc_storage::{AccountUpdates, StakeUpdates, StorageError};

/// Re-exported so existing callers (`circuit_staking::stake_subaccount`, etc.)
/// keep working unchanged — the implementations moved to `xc_primitives`
/// because genesis construction in `xc-storage` needs them too, and
/// `xc-storage` can't depend on this crate (this crate depends on it). See
/// the doc comments on the originals in `xc_primitives::state` for why.
pub use xc_primitives::{reward_pool_account, stake_subaccount, treasury_account};

/// Devnet stub — tune once real economics are decided.
pub const UNBONDING_BLOCKS: u64 = 100;

/// 4.3 ARX/block in IUM — whitepaper §9.1/9.3 Y1 target (750M-ARX pool,
/// 15% of the 5B fixed non-mintable supply, emitted to validators).
/// Flat devnet-stub rate, no 8%/yr decay curve — tune once real economics
/// are decided, same as `UNBONDING_BLOCKS`.
pub const REWARD_PER_BLOCK: u128 = 4_300_000_000;

/// Fee split, whitepaper §9.4: 30% to the block proposer, 20% to treasury,
/// remaining 50% stays burned (the sender already paid the full fee in
/// `charge_action_fee`; this module never credits that other 50% anywhere).
/// Basis points out of 10_000 so the shares are exact integer fractions.
const FEE_PROPOSER_BPS: u128 = 3_000;
const FEE_TREASURY_BPS: u128 = 2_000;

/// Whitepaper §9.5: max 10,000,000 ARX delegated to a single validator.
/// Since this module allows only one master per validator (see
/// `ValidatorHasOtherMaster` below), this caps that one master's total.
pub const MAX_DELEGATION_PER_VALIDATOR: u128 = 10_000_000 * 1_000_000_000;

/// Whitepaper §7.3: 0.01% of total stake burned per missed block. Applied
/// automatically (see `apply_downtime_slash`), not via submitted evidence —
/// every node deterministically agrees on who missed a slot from the same
/// stored block, so there's nothing to prove.
const DOWNTIME_SLASH_BPS: u128 = 1;

/// Stub taxonomy — no consensus fault-detection exists yet in this
/// codebase; extend when a real fault detector lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashReason {
    DoubleSign,
    Downtime,
}

#[derive(Error, Debug)]
pub enum StakingError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("invalid nonce {master}: expected {expected}, got {got}")]
    InvalidNonce { master: Address, expected: u64, got: u64 },
    #[error("stake amount must be greater than zero")]
    ZeroAmount,
    #[error("insufficient balance {master}: {balance}, needs {amount}")]
    InsufficientBalance { master: Address, balance: u128, amount: u128 },
    #[error("validator {validator} is already controlled by a different master")]
    ValidatorHasOtherMaster { validator: Address },
    #[error("{master} has no active allocation to validator {validator}")]
    NoActiveAllocation { master: Address, validator: Address },
    #[error(
        "{master} already has an unbonding batch in flight for validator {validator}; \
         wait for it to resolve before staking or unstaking again"
    )]
    AlreadyUnbonding { master: Address, validator: Address },
    #[error("cannot unstake {amount} from {master}'s {active} active stake on {validator}")]
    InsufficientStake { master: Address, validator: Address, active: u128, amount: u128 },
    #[error("validator {validator} has no stake to slash")]
    NoStakeForValidator { validator: Address },
    #[error(
        "stake would push {validator}'s total delegation to {new_total}, over the \
         {MAX_DELEGATION_PER_VALIDATOR} cap"
    )]
    DelegationCapExceeded { validator: Address, new_total: u128 },
}

fn default_account() -> AccountEntry {
    AccountEntry { balance: 0, nonce: 0, identity_hash: None, zk_identity_verified: false }
}

/// Once per block: pays the proposer the flat block reward (capped at
/// whatever's left in `reward_pool_account` — never exceeds it, so total
/// emission is bounded by the pool's genesis balance) plus the proposer's
/// cut of `fees_collected`, and credits treasury its cut. `fees_collected`
/// is `applied_action_count * per-action fee`, computed by the caller
/// (chain-specific — this module doesn't know the fee amount, only how to
/// split it once collected). The other fee share was already burned when
/// each action was dispatched (sender debited, nobody credited); this
/// function only ever adds, never re-debits the sender.
pub fn apply_block_reward(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    proposer: &Address,
    fees_collected: u128,
) -> Result<AccountUpdates, StorageError> {
    let pool_account = reward_pool_account();
    let treasury = treasury_account();

    let mut pool_entry = accounts(&pool_account)?.unwrap_or_else(default_account);
    let block_reward = REWARD_PER_BLOCK.min(pool_entry.balance);
    pool_entry.balance -= block_reward;

    let proposer_fee_share = fees_collected * FEE_PROPOSER_BPS / 10_000;
    let treasury_fee_share = fees_collected * FEE_TREASURY_BPS / 10_000;

    let mut proposer_entry = accounts(proposer)?.unwrap_or_else(default_account);
    proposer_entry.balance += block_reward + proposer_fee_share;

    let mut treasury_entry = accounts(&treasury)?.unwrap_or_else(default_account);
    treasury_entry.balance += treasury_fee_share;

    let mut updates = HashMap::new();
    updates.insert(pool_account, pool_entry);
    updates.insert(proposer.clone(), proposer_entry);
    updates.insert(treasury, treasury_entry);
    Ok(AccountUpdates(updates))
}

/// Debits `master`, credits `validator`'s sub-account, upserts the
/// allocation. Rejects a second master for a validator already controlled,
/// and rejects topping up while an unbonding batch is in flight (must fully
/// resolve first — avoids ambiguous "topping up while partially unbonding"
/// semantics).
pub fn apply_stake(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    allocation: impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    validator_masters: impl Fn(&Address) -> Result<Vec<Address>, StorageError>,
    master: &Address,
    nonce: u64,
    validator: &Address,
    amount: u128,
    now_height: u64,
) -> Result<(AccountUpdates, StakeUpdates), StakingError> {
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }

    let mut master_entry = accounts(master)?.unwrap_or_else(default_account);
    if nonce != master_entry.nonce {
        return Err(StakingError::InvalidNonce { master: master.clone(), expected: master_entry.nonce, got: nonce });
    }
    if master_entry.balance < amount {
        return Err(StakingError::InsufficientBalance {
            master: master.clone(),
            balance: master_entry.balance,
            amount,
        });
    }

    let masters = validator_masters(validator)?;
    if masters.iter().any(|m| m != master) {
        return Err(StakingError::ValidatorHasOtherMaster { validator: validator.clone() });
    }

    let existing = allocation(master, validator)?;
    if let Some(existing) = &existing {
        if existing.unbonding.is_some() {
            return Err(StakingError::AlreadyUnbonding { master: master.clone(), validator: validator.clone() });
        }
    }

    let current_total = existing.as_ref().map(|e| e.active_amount).unwrap_or(0);
    let new_total = current_total + amount;
    if new_total > MAX_DELEGATION_PER_VALIDATOR {
        return Err(StakingError::DelegationCapExceeded { validator: validator.clone(), new_total });
    }

    let sub_account = stake_subaccount(validator);
    let mut sub_entry = accounts(&sub_account)?.unwrap_or_else(default_account);

    master_entry.balance -= amount;
    master_entry.nonce += 1;
    sub_entry.balance += amount;

    let new_allocation = match existing {
        Some(mut existing) => {
            existing.active_amount += amount;
            existing.updated_at = now_height;
            existing
        }
        None => StakeAllocation {
            master: master.clone(),
            validator: validator.clone(),
            active_amount: amount,
            unbonding: None,
            created_at: now_height,
            updated_at: now_height,
        },
    };

    let mut account_updates = HashMap::new();
    account_updates.insert(master.clone(), master_entry);
    account_updates.insert(sub_account, sub_entry);

    let mut stake_updates = StakeUpdates::default();
    stake_updates.allocations.insert((master.clone(), validator.clone()), Some(new_allocation));
    stake_updates.validator_index.insert(validator.clone(), vec![master.clone()]);

    Ok((AccountUpdates(account_updates), stake_updates))
}

/// Splits `active_amount` from an existing allocation into an `Unbonding`
/// batch. Coins stay in the sub-account during the unbonding window — that's
/// what makes them slashable while unbonding. v1 allows at most one
/// unbonding batch in flight per `(master, validator)` pair.
pub fn apply_unstake(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    allocation: impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    master: &Address,
    nonce: u64,
    validator: &Address,
    amount: u128,
    now_height: u64,
) -> Result<(AccountUpdates, StakeUpdates), StakingError> {
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }

    let mut master_entry = accounts(master)?.unwrap_or_else(default_account);
    if nonce != master_entry.nonce {
        return Err(StakingError::InvalidNonce { master: master.clone(), expected: master_entry.nonce, got: nonce });
    }

    let mut existing = allocation(master, validator)?
        .ok_or_else(|| StakingError::NoActiveAllocation { master: master.clone(), validator: validator.clone() })?;
    if existing.unbonding.is_some() {
        return Err(StakingError::AlreadyUnbonding { master: master.clone(), validator: validator.clone() });
    }
    if amount > existing.active_amount {
        return Err(StakingError::InsufficientStake {
            master: master.clone(),
            validator: validator.clone(),
            active: existing.active_amount,
            amount,
        });
    }

    existing.active_amount -= amount;
    existing.unbonding = Some(Unbonding { amount, unlock_at_height: now_height + UNBONDING_BLOCKS });
    existing.updated_at = now_height;
    master_entry.nonce += 1;

    let mut account_updates = HashMap::new();
    account_updates.insert(master.clone(), master_entry);

    let mut stake_updates = StakeUpdates::default();
    stake_updates.allocations.insert((master.clone(), validator.clone()), Some(existing));

    Ok((AccountUpdates(account_updates), stake_updates))
}

/// Burns `amount` (capped at what's staked) from `validator`'s sub-account,
/// hitting `active_amount` first and spilling into an in-flight
/// `unbonding.amount` — this is the whole point of the unbonding delay,
/// funds must stay slashable while unbonding. Not wired to any
/// `ActionPayload` variant: unreachable from RPC/mempool by construction,
/// meant for direct/test callers until a fault detector exists.
pub fn apply_slash(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    allocation: impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    validator_masters: impl Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validator: &Address,
    amount: u128,
    _reason: SlashReason,
    now_height: u64,
) -> Result<(AccountUpdates, StakeUpdates), StakingError> {
    let masters = validator_masters(validator)?;
    let master = masters
        .first()
        .cloned()
        .ok_or_else(|| StakingError::NoStakeForValidator { validator: validator.clone() })?;
    let mut existing = allocation(&master, validator)?
        .ok_or_else(|| StakingError::NoStakeForValidator { validator: validator.clone() })?;

    let total = existing.active_amount + existing.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);
    let slash_amount = amount.min(total);

    let from_active = slash_amount.min(existing.active_amount);
    existing.active_amount -= from_active;
    let remaining = slash_amount - from_active;
    if remaining > 0 {
        if let Some(unbonding) = &mut existing.unbonding {
            unbonding.amount -= remaining;
            if unbonding.amount == 0 {
                existing.unbonding = None;
            }
        }
    }
    existing.updated_at = now_height;

    let sub_account = stake_subaccount(validator);
    let mut sub_entry = accounts(&sub_account)?.unwrap_or_else(default_account);
    // ponytail: saturating, not `-=`. A well-formed allocation (created via
    // `apply_stake`) always has sub-account balance >= active_amount, so this
    // never actually clamps on that path. Genesis validators are the
    // exception — their StakeAllocation is synthesized directly (see
    // `Snapshot::batch_entries` in xc_storage) without ever crediting a
    // matching sub-account balance, so slashing one for real would otherwise
    // underflow a u128 and panic. Clamping to 0 is the safe direction to
    // fail in for a money-boundary bug: worst case a slash burns less than
    // the ledger says, never the reverse.
    sub_entry.balance = sub_entry.balance.saturating_sub(slash_amount);
    // ponytail: burned, not credited anywhere — deliberate v1 default. A
    // treasury-credit would go right here once that circuit exists.

    let mut account_updates = HashMap::new();
    account_updates.insert(sub_account, sub_entry);

    let mut stake_updates = StakeUpdates::default();
    if existing.active_amount == 0 && existing.unbonding.is_none() {
        stake_updates.allocations.insert((master.clone(), validator.clone()), None);
        stake_updates.validator_index.insert(validator.clone(), Vec::new());
    } else {
        stake_updates.allocations.insert((master, validator.clone()), Some(existing));
    }

    Ok((AccountUpdates(account_updates), stake_updates))
}

/// Once per accepted/produced block: if `primary` (the height's no-timeout
/// round-robin proposer, i.e. `xc_primitives::expected_proposer`) isn't who
/// actually produced the block, burns a small downtime slash from their
/// stake. No evidence submission needed — every node computes `primary` and
/// `actual_proposer` from the same stored block, so both sides agree without
/// proof. No-ops (rather than erroring) if the primary has nothing staked
/// left to slash — a missed slot from an already-exiting validator isn't a
/// block-production failure.
pub fn apply_downtime_slash(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    allocation: impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    validator_masters: impl Fn(&Address) -> Result<Vec<Address>, StorageError>,
    primary: &Address,
    actual_proposer: &Address,
    now_height: u64,
) -> Result<(AccountUpdates, StakeUpdates), StorageError> {
    if primary == actual_proposer {
        return Ok(Default::default());
    }
    let masters = validator_masters(primary)?;
    let Some(master) = masters.first() else {
        return Ok(Default::default());
    };
    let Some(existing) = allocation(master, primary)? else {
        return Ok(Default::default());
    };
    let total = existing.active_amount + existing.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);
    let amount = total * DOWNTIME_SLASH_BPS / 10_000;
    if amount == 0 {
        return Ok(Default::default());
    }

    match apply_slash(accounts, allocation, validator_masters, primary, amount, SlashReason::Downtime, now_height) {
        Ok(result) => Ok(result),
        Err(StakingError::Storage(err)) => Err(err),
        Err(_) => Ok(Default::default()),
    }
}

/// Folds every `due` allocation's matured unbonding batch back to its
/// master's spendable balance. `due` must already be filtered by the
/// caller (`unlock_at_height <= current height`) — this is a pure fold,
/// not a lookup, so multiple due allocations sharing a master accumulate
/// correctly in one call.
pub fn resolve_due_unbonding(
    accounts: impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    due: Vec<StakeAllocation>,
) -> Result<(AccountUpdates, StakeUpdates), StorageError> {
    let mut overlay: HashMap<Address, AccountEntry> = HashMap::new();
    let mut stake_updates = StakeUpdates::default();

    for mut allocation in due {
        let Some(unbonding) = allocation.unbonding.take() else {
            continue;
        };

        let mut master_entry = match overlay.get(&allocation.master) {
            Some(entry) => entry.clone(),
            None => accounts(&allocation.master)?.unwrap_or_else(default_account),
        };
        master_entry.balance += unbonding.amount;
        overlay.insert(allocation.master.clone(), master_entry);

        let sub_account = stake_subaccount(&allocation.validator);
        let mut sub_entry = match overlay.get(&sub_account) {
            Some(entry) => entry.clone(),
            None => accounts(&sub_account)?.unwrap_or_else(default_account),
        };
        sub_entry.balance -= unbonding.amount;
        overlay.insert(sub_account, sub_entry);

        if allocation.active_amount == 0 {
            stake_updates
                .allocations
                .insert((allocation.master.clone(), allocation.validator.clone()), None);
            stake_updates.validator_index.insert(allocation.validator.clone(), Vec::new());
        } else {
            let key = (allocation.master.clone(), allocation.validator.clone());
            stake_updates.allocations.insert(key, Some(allocation));
        }
    }

    Ok((AccountUpdates(overlay), stake_updates))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_storage::ArxiumDb;

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-staking-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    fn write_balance(db: &ArxiumDb, address: &Address, balance: u128) {
        let mut updates = HashMap::new();
        updates.insert(address.clone(), AccountEntry { balance, nonce: 0, identity_hash: None, zk_identity_verified: false });
        db.write_batch(&AccountUpdates(updates)).unwrap();
    }

    fn commit(db: &ArxiumDb, accounts: AccountUpdates, stakes: StakeUpdates) {
        db.write_batches(&[&accounts, &stakes]).unwrap();
    }

    #[test]
    fn stake_debits_master_and_credits_subaccount_by_the_same_amount() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            400,
            10,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        assert_eq!(db.get_account(&master).unwrap().unwrap().balance, 600);
        let sub = stake_subaccount(&validator);
        assert_eq!(db.get_account(&sub).unwrap().unwrap().balance, 400);
        let allocation = db.get_stake_allocation(&master, &validator).unwrap().unwrap();
        assert_eq!(allocation.active_amount, 400);
        assert_eq!(db.get_stakes_by_validator(&validator).unwrap(), vec![master]);
    }

    #[test]
    fn stake_rejects_a_second_master_for_an_already_controlled_validator() {
        let db = temp_db();
        let alice = addr(1);
        let bob = addr(3);
        let validator = addr(2);
        write_balance(&db, &alice, 1000);
        write_balance(&db, &bob, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &alice,
            0,
            &validator,
            100,
            10,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let err = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &bob,
            0,
            &validator,
            100,
            10,
        )
        .unwrap_err();
        assert!(matches!(err, StakingError::ValidatorHasOtherMaster { .. }));
    }

    #[test]
    fn partial_unstake_splits_active_and_unbonding_in_the_same_record() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            500,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let (accounts, stakes) = apply_unstake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            &master,
            1,
            &validator,
            200,
            50,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let allocation = db.get_stake_allocation(&master, &validator).unwrap().unwrap();
        assert_eq!(allocation.active_amount, 300, "remaining stake must stay active");
        let unbonding = allocation.unbonding.expect("requested amount must be unbonding");
        assert_eq!(unbonding.amount, 200);
        assert_eq!(unbonding.unlock_at_height, 50 + UNBONDING_BLOCKS);

        // Coins have not moved — still fully in the sub-account, slashable.
        let sub = stake_subaccount(&validator);
        assert_eq!(db.get_account(&sub).unwrap().unwrap().balance, 500);
    }

    #[test]
    fn unstake_rejects_a_second_batch_while_one_is_already_unbonding() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            500,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let (accounts, stakes) = apply_unstake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            &master,
            1,
            &validator,
            200,
            2,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let err = apply_unstake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            &master,
            2,
            &validator,
            100,
            3,
        )
        .unwrap_err();
        assert!(matches!(err, StakingError::AlreadyUnbonding { .. }));
    }

    #[test]
    fn slash_hits_both_active_and_unbonding_allocations() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            500,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        let (accounts, stakes) = apply_unstake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            &master,
            1,
            &validator,
            200,
            2,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        // 300 active, 200 unbonding.

        let (accounts, stakes) = apply_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &validator,
            350,
            SlashReason::DoubleSign,
            3,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let allocation = db.get_stake_allocation(&master, &validator).unwrap().unwrap();
        assert_eq!(allocation.active_amount, 0, "active portion slashed first, fully consumed");
        assert_eq!(allocation.unbonding.unwrap().amount, 150, "remainder spills into unbonding");
        let sub = stake_subaccount(&validator);
        assert_eq!(db.get_account(&sub).unwrap().unwrap().balance, 150, "burned, no credit anywhere");
    }

    #[test]
    fn slash_removes_the_allocation_once_it_nets_to_zero() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            500,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let (accounts, stakes) = apply_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &validator,
            500,
            SlashReason::Downtime,
            2,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        assert!(db.get_stake_allocation(&master, &validator).unwrap().is_none());
        assert_eq!(db.get_stakes_by_validator(&validator).unwrap(), Vec::<Address>::new());
    }

    #[test]
    fn total_supply_is_conserved_across_stake_and_unstake_and_only_drops_on_slash() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);

        let supply = |db: &ArxiumDb| {
            db.get_account(&master).unwrap().unwrap().balance
                + db.get_account(&stake_subaccount(&validator)).unwrap().map(|a| a.balance).unwrap_or(0)
        };
        assert_eq!(supply(&db), 1000);

        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            600,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        assert_eq!(supply(&db), 1000, "stake must not mint or burn");

        let (accounts, stakes) = apply_unstake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            &master,
            1,
            &validator,
            200,
            2,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        assert_eq!(supply(&db), 1000, "unstake request alone must not move funds yet");

        let (accounts, stakes) = apply_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &validator,
            150,
            SlashReason::DoubleSign,
            3,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        assert_eq!(supply(&db), 850, "slash burns — supply must drop by exactly the slashed amount");

        let due = db.get_allocations_with_unbonding_due(2 + UNBONDING_BLOCKS).unwrap();
        let (accounts, stakes) = resolve_due_unbonding(|a| db.get_account(a), due).unwrap();
        commit(&db, accounts, stakes);
        assert_eq!(supply(&db), 850, "unbonding resolution moves funds within the same supply");
        assert_eq!(db.get_account(&master).unwrap().unwrap().balance, 400 + 200);
    }

    #[test]
    fn block_reward_splits_fees_and_pays_proposer_from_the_pool_without_minting() {
        let db = temp_db();
        let proposer = addr(9);
        write_balance(&db, &reward_pool_account(), 10_000_000_000); // pool: ~10 ARX

        let supply = |db: &ArxiumDb| {
            db.get_account(&reward_pool_account()).unwrap().map(|a| a.balance).unwrap_or(0)
                + db.get_account(&proposer).unwrap().map(|a| a.balance).unwrap_or(0)
                + db.get_account(&treasury_account()).unwrap().map(|a| a.balance).unwrap_or(0)
        };
        let pool_before = supply(&db);

        // 10 actions at 1_000_000 IUM fee each == 10_000_000 collected.
        let updates = apply_block_reward(|a| db.get_account(a), &proposer, 10_000_000).unwrap();
        db.write_batch(&updates).unwrap();

        assert_eq!(
            db.get_account(&proposer).unwrap().unwrap().balance,
            REWARD_PER_BLOCK + 3_000_000,
            "proposer gets the flat block reward plus its 30% fee share"
        );
        assert_eq!(
            db.get_account(&treasury_account()).unwrap().unwrap().balance,
            2_000_000,
            "treasury gets its 20% fee share"
        );
        assert_eq!(
            db.get_account(&reward_pool_account()).unwrap().unwrap().balance,
            10_000_000_000 - REWARD_PER_BLOCK,
            "block reward is debited from the pool, never minted"
        );
        // Fee's other 50% (5_000_000) was already burned by charge_action_fee
        // before this ever runs — not this function's job to account for it.
        assert_eq!(
            supply(&db),
            pool_before + REWARD_PER_BLOCK - REWARD_PER_BLOCK + 5_000_000,
            "sum across pool+proposer+treasury only grows by the non-burned fee share"
        );
    }

    #[test]
    fn block_reward_caps_at_the_pool_balance_once_it_runs_dry() {
        let db = temp_db();
        let proposer = addr(9);
        write_balance(&db, &reward_pool_account(), 1_000_000); // far less than REWARD_PER_BLOCK

        let updates = apply_block_reward(|a| db.get_account(a), &proposer, 0).unwrap();
        db.write_batch(&updates).unwrap();

        assert_eq!(
            db.get_account(&proposer).unwrap().unwrap().balance,
            1_000_000,
            "capped at whatever the pool had left, not the full REWARD_PER_BLOCK"
        );
        assert_eq!(db.get_account(&reward_pool_account()).unwrap().unwrap().balance, 0);

        // Pool empty: further blocks mint nothing further, forever.
        let updates = apply_block_reward(|a| db.get_account(a), &proposer, 0).unwrap();
        db.write_batch(&updates).unwrap();
        assert_eq!(db.get_account(&proposer).unwrap().unwrap().balance, 1_000_000);
    }

    #[test]
    fn stake_rejects_delegation_over_the_cap() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, MAX_DELEGATION_PER_VALIDATOR + 1);

        let err = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            MAX_DELEGATION_PER_VALIDATOR + 1,
            10,
        )
        .unwrap_err();
        assert!(matches!(err, StakingError::DelegationCapExceeded { .. }));

        // Right at the cap still succeeds.
        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            MAX_DELEGATION_PER_VALIDATOR,
            10,
        )
        .unwrap();
        commit(&db, accounts, stakes);
        assert_eq!(
            db.get_stake_allocation(&master, &validator).unwrap().unwrap().active_amount,
            MAX_DELEGATION_PER_VALIDATOR
        );

        // A top-up that would push the same master over the cap is rejected too.
        // (write directly, not via `write_balance`, so the nonce `apply_stake`
        // just bumped to 1 above survives — `write_balance` always resets it to 0.)
        let mut entry = db.get_account(&master).unwrap().unwrap();
        entry.balance = 1;
        let mut updates = HashMap::new();
        updates.insert(master.clone(), entry);
        db.write_batch(&AccountUpdates(updates)).unwrap();

        let err = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            1,
            &validator,
            1,
            11,
        )
        .unwrap_err();
        assert!(matches!(err, StakingError::DelegationCapExceeded { .. }));
    }

    #[test]
    fn downtime_slash_is_a_noop_when_primary_matches_actual() {
        let db = temp_db();
        let master = addr(1);
        let validator = addr(2);
        write_balance(&db, &master, 1000);
        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &validator,
            500,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let (accounts, stakes) = apply_downtime_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &validator,
            &validator,
            2,
        )
        .unwrap();
        assert!(accounts.0.is_empty());
        assert!(stakes.allocations.is_empty());
        let sub = stake_subaccount(&validator);
        assert_eq!(db.get_account(&sub).unwrap().unwrap().balance, 500, "untouched");
    }

    #[test]
    fn downtime_slash_burns_a_small_share_when_primary_missed_its_slot() {
        let db = temp_db();
        let master = addr(1);
        let primary = addr(2);
        let actual = addr(3);
        write_balance(&db, &master, 1_000_000_000);
        let (accounts, stakes) = apply_stake(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &master,
            0,
            &primary,
            1_000_000_000,
            1,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let (accounts, stakes) = apply_downtime_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &primary,
            &actual,
            2,
        )
        .unwrap();
        commit(&db, accounts, stakes);

        let allocation = db.get_stake_allocation(&master, &primary).unwrap().unwrap();
        assert_eq!(
            allocation.active_amount, 999_900_000,
            "0.01% of 1_000_000_000 == 100_000 burned"
        );
    }

    #[test]
    fn downtime_slash_is_a_noop_when_primary_has_no_stake() {
        let db = temp_db();
        let primary = addr(9);
        let actual = addr(3);

        let (accounts, stakes) = apply_downtime_slash(
            |a| db.get_account(a),
            |m, v| db.get_stake_allocation(m, v),
            |v| db.get_stakes_by_validator(v),
            &primary,
            &actual,
            2,
        )
        .unwrap();
        assert!(accounts.0.is_empty());
        assert!(stakes.allocations.is_empty());
    }
}
