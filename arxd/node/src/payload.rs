use serde::{Deserialize, Serialize};
use xc_executor::BlockUpdates;
use xc_primitives::{AccountEntry, Action, Address, StakeAllocation, ValidatorChange, ValidatorEntry};
use xc_storage::StorageError;

/// Devnet stub — tune once real economics are decided. Below this,
/// `JoinValidator` is rejected before `circuit_staking::apply_stake` even
/// runs: round-robin proposer selection ignores stake size, so without a
/// floor "becoming a validator" would be free.
pub const MIN_VALIDATOR_STAKE: u128 = 1_000;

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer { to: Address, amount: u128 },
    /// Self-staking: routed through `circuit_staking::apply_stake` with
    /// `master == validator == sender`, so it's held in the same
    /// `stake_subaccount` mechanism regular delegators use — same balance
    /// check, same "already controlled by another master" rejection, no new
    /// bookkeeping. Takes effect one block after this action lands
    /// (`xc_executor::accept_block`'s effective-height rule) — can't vote
    /// itself into this block's own proposer slot. `stake` on
    /// `ValidatorEntry` is informational only; `ValidatorSetSnapshot` never
    /// persists it, so the `StakeAllocation` for `(sender, sender)` is the
    /// real source of truth for how much a validator has at stake.
    JoinValidator { stake: u128 },
    /// Self-service removal, now routed through
    /// `circuit_staking::apply_unstake` for the sender's full self-stake
    /// before the `ValidatorChange::Leave` is allowed. Leaving drops you
    /// from the proposer rotation immediately, but the stake sits in
    /// `Unbonding` for `circuit_staking::UNBONDING_BLOCKS` — and stays
    /// slashable that whole time (`circuit_staking::apply_slash` treats
    /// unbonding funds as fair game). Rejected if the sender isn't currently
    /// a validator, or if they're the last one — an empty validator set
    /// means `expected_proposer` returns `None` forever and the chain can
    /// never produce another block (the same deadlock hit live this session
    /// from running `--bootnode` on two machines, self-inflicted here
    /// instead).
    LeaveValidator,
    /// MW-signature-only stake into a validator's sub-account
    /// (`circuit_staking::stake_subaccount`). See `circuit_staking::apply_stake`.
    Stake { validator: Address, amount: u128 },
    /// MW-signature-only partial or full unstake, subject to
    /// `circuit_staking::UNBONDING_BLOCKS`. See `circuit_staking::apply_unstake`.
    /// There is deliberately no `Slash` variant here — slashing is never
    /// user-submitted, so it's unreachable from RPC/mempool by construction
    /// (see `circuit_staking::apply_slash`).
    Unstake { validator: Address, amount: u128 },
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

/// The payload → circuit mapping `xc_executor::execute_actions` calls per
/// action. This is the only place CoreChain decides what a payload variant
/// means. `validators` is the set as of the start of this block — the same
/// one `accept_block`/`produce_block` will fold this action's
/// `ValidatorChange` onto. `current_height` is the height of the block being
/// built/accepted — needed to timestamp `Stake`/`Unstake`'s unbonding clock.
pub fn dispatch(
    action: &ChainAction,
    lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    stake_lookup: &dyn Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    validator_masters_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => Ok(BlockUpdates {
            accounts: circuit_account::apply_transfer(lookup, &action.sender, action.nonce, to, *amount)?,
            ..Default::default()
        }),
        ActionPayload::JoinValidator { stake } => {
            // The floor is on total self-stake, not this call's delta — a
            // validator already at/above it topping up further shouldn't be
            // re-charged the whole minimum again.
            let existing_active = stake_lookup(&action.sender, &action.sender)?
                .map(|a| a.active_amount)
                .unwrap_or(0);
            if existing_active + *stake < MIN_VALIDATOR_STAKE {
                anyhow::bail!(
                    "stake {stake} is below the minimum validator stake {MIN_VALIDATOR_STAKE}"
                );
            }
            let (accounts, stakes) = circuit_staking::apply_stake(
                lookup,
                stake_lookup,
                validator_masters_lookup,
                &action.sender,
                action.nonce,
                &action.sender,
                *stake,
                current_height,
            )?;
            let change = ValidatorChange::Join(action.sender.clone(), ValidatorEntry { stake: *stake });
            Ok(BlockUpdates { accounts, stakes, validator_change: Some(change) })
        }
        ActionPayload::LeaveValidator => {
            if !validators.contains(&action.sender) {
                anyhow::bail!("{} is not a current validator", action.sender);
            }
            if validators.len() <= 1 {
                anyhow::bail!("cannot remove the last validator, chain would stall forever");
            }
            let self_stake = stake_lookup(&action.sender, &action.sender)?.ok_or_else(|| {
                anyhow::anyhow!("{} has no self-stake to unstake", action.sender)
            })?;
            let (accounts, stakes) = circuit_staking::apply_unstake(
                lookup,
                stake_lookup,
                &action.sender,
                action.nonce,
                &action.sender,
                self_stake.active_amount,
                current_height,
            )?;
            Ok(BlockUpdates {
                accounts,
                stakes,
                validator_change: Some(ValidatorChange::Leave(action.sender.clone())),
            })
        }
        ActionPayload::Stake { validator, amount } => {
            let (accounts, stakes) = circuit_staking::apply_stake(
                lookup,
                stake_lookup,
                validator_masters_lookup,
                &action.sender,
                action.nonce,
                validator,
                *amount,
                current_height,
            )?;
            Ok(BlockUpdates { accounts, stakes, ..Default::default() })
        }
        ActionPayload::Unstake { validator, amount } => {
            let (accounts, stakes) = circuit_staking::apply_unstake(
                lookup,
                stake_lookup,
                &action.sender,
                action.nonce,
                validator,
                *amount,
                current_height,
            )?;
            Ok(BlockUpdates { accounts, stakes, ..Default::default() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(_addr: &Address) -> Result<Option<AccountEntry>, StorageError> {
        Ok(None)
    }

    fn stake_lookup(_master: &Address, _validator: &Address) -> Result<Option<StakeAllocation>, StorageError> {
        Ok(None)
    }

    fn validator_masters_lookup(_validator: &Address) -> Result<Vec<Address>, StorageError> {
        Ok(Vec::new())
    }

    fn make_lookup(
        accounts: HashMap<Address, AccountEntry>,
    ) -> impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError> {
        move |addr| Ok(accounts.get(addr).cloned())
    }

    fn make_stake_lookup(
        allocations: HashMap<(Address, Address), StakeAllocation>,
    ) -> impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError> {
        move |master, validator| Ok(allocations.get(&(master.clone(), validator.clone())).cloned())
    }

    fn funded(balance: u128) -> AccountEntry {
        AccountEntry { balance, nonce: 0, identity_hash: None }
    }

    fn self_allocation(addr: &Address, active_amount: u128) -> StakeAllocation {
        StakeAllocation {
            master: addr.clone(),
            validator: addr.clone(),
            active_amount,
            unbonding: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn leave_validator_rejected_when_sender_is_the_last_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let err = match dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[alice], 0) {
            Err(err) => err,
            Ok(_) => panic!("expected leaving the last validator to be rejected"),
        };
        assert!(err.to_string().contains("last validator"));
    }

    #[test]
    fn leave_validator_succeeds_when_others_remain() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        let stake_lookup =
            make_stake_lookup(HashMap::from([((alice.clone(), alice.clone()), self_allocation(&alice, 2_000))]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let updates =
            dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[alice.clone(), bob], 0).unwrap();
        assert!(matches!(updates.validator_change, Some(ValidatorChange::Leave(a)) if a == alice));
    }

    #[test]
    fn join_validator_debits_sender_and_credits_own_subaccount() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(5_000))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator { stake: MIN_VALIDATOR_STAKE },
        };

        let updates =
            dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[], 10).unwrap();

        assert!(matches!(updates.validator_change, Some(ValidatorChange::Join(ref a, _)) if *a == alice));
        assert_eq!(updates.accounts.0.get(&alice).unwrap().balance, 5_000 - MIN_VALIDATOR_STAKE);
        let sub = circuit_staking::stake_subaccount(&alice);
        assert_eq!(updates.accounts.0.get(&sub).unwrap().balance, MIN_VALIDATOR_STAKE);
        let allocation = updates.stakes.allocations.get(&(alice.clone(), alice)).unwrap().clone().unwrap();
        assert_eq!(allocation.active_amount, MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn second_join_tops_up_rather_than_double_charging() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(10_000))]));
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            self_allocation(&alice, MIN_VALIDATOR_STAKE),
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator { stake: 500 },
        };

        let updates =
            dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[alice.clone()], 10).unwrap();

        let allocation = updates.stakes.allocations.get(&(alice.clone(), alice)).unwrap().clone().unwrap();
        assert_eq!(allocation.active_amount, MIN_VALIDATOR_STAKE + 500, "top-up adds to the existing self-stake");
    }

    #[test]
    fn join_validator_rejected_with_insufficient_balance() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(100))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator { stake: MIN_VALIDATOR_STAKE },
        };

        let err = dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[], 10).unwrap_err();
        assert!(err.to_string().contains("insufficient balance") || err.to_string().contains("InsufficientBalance"));
    }

    #[test]
    fn join_validator_rejected_below_minimum_stake() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(10_000))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator { stake: MIN_VALIDATOR_STAKE - 1 },
        };

        let err = dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[], 10).unwrap_err();
        assert!(err.to_string().contains("minimum validator stake"));
    }

    #[test]
    fn leave_validator_starts_unbonding_rather_than_instant_return() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            self_allocation(&alice, MIN_VALIDATOR_STAKE),
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let updates =
            dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[alice.clone(), bob], 5).unwrap();

        assert!(matches!(updates.validator_change, Some(ValidatorChange::Leave(ref a)) if *a == alice));
        let allocation = updates.stakes.allocations.get(&(alice.clone(), alice.clone())).unwrap().clone().unwrap();
        assert_eq!(allocation.active_amount, 0, "full self-stake moves out of active");
        let unbonding = allocation.unbonding.expect("leaving must start an unbonding batch, not an instant refund");
        assert_eq!(unbonding.amount, MIN_VALIDATOR_STAKE);
        assert_eq!(unbonding.unlock_at_height, 5 + circuit_staking::UNBONDING_BLOCKS);
        // No balance credited back yet — still sitting in the sub-account, slashable.
        assert_eq!(updates.accounts.0.get(&alice).map(|a| a.balance).unwrap_or(0), 0);
    }

    #[test]
    fn leave_validator_rejected_while_already_unbonding() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        // Active portion left nonzero (e.g. a prior manual partial Unstake)
        // so the `amount == 0` guard in apply_unstake doesn't fire first —
        // this test is specifically about the AlreadyUnbonding rejection.
        let mut allocation = self_allocation(&alice, 300);
        allocation.unbonding = Some(xc_primitives::Unbonding { amount: 700, unlock_at_height: 100 });
        let stake_lookup = make_stake_lookup(HashMap::from([((alice.clone(), alice.clone()), allocation)]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let err =
            dispatch(&action, &lookup, &stake_lookup, &validator_masters_lookup, &[alice.clone(), bob], 5).unwrap_err();
        assert!(err.to_string().contains("already has an unbonding batch"));
    }
}
