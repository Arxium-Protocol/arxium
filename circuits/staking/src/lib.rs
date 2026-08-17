use std::collections::HashMap;

use sha2::{Digest, Sha256};
use thiserror::Error;
use xc_primitives::{AccountEntry, Address, StakeAllocation, Unbonding};
use xc_storage::{AccountUpdates, StakeUpdates, StorageError};

/// Devnet stub — tune once real economics are decided.
pub const UNBONDING_BLOCKS: u64 = 100;

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
}

fn default_account() -> AccountEntry {
    AccountEntry { balance: 0, nonce: 0, identity_hash: None, zk_identity_verified: false }
}

/// Deterministically derives the address staked coins for `validator` are
/// held in. Any node computes this locally — no lookup table needed.
pub fn stake_subaccount(validator: &Address) -> Address {
    // ponytail: domain-separated hash; grep confirmed no other
    // from_pubkey_bytes-as-hash usage in xc-primitives to collide with.
    let preimage = [b"xc-stake-subaccount:".as_slice(), validator.to_string().as_bytes()].concat();
    let digest = Sha256::digest(preimage);
    Address::from_pubkey_bytes(&digest).expect("sha256 digest is always 32 bytes")
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
    sub_entry.balance -= slash_amount;
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
}
