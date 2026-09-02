// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_bls::BlsPublicKey;
use xc_circuit::{AccountKey, KvRead, StakeByValidatorKey, StakeKey};
use xc_executor::BlockUpdates;
use xc_primitives::{Address, ValidatorChange, ValidatorEntry};
use xc_storage::{BlockView, BlsKeyRegistration, StorageError};

use crate::ChainAction;
use crate::consensus::validated_bls_pubkey;

/// 100,000 ARX, in IUM (ARX's base unit — 1 ARX = 1_000_000_000 IUM). Below
/// this, `JoinValidator` is rejected before `circuit_staking::apply_stake`
/// even runs: round-robin proposer selection ignores stake size, so without
/// a floor "becoming a validator" would be free.
pub const MIN_VALIDATOR_STAKE: u128 = 100_000 * 1_000_000_000;

/// `sender == validator` covers self-service management, unchanged from
/// before delegation existed. `sender != validator` is only ever allowed if
/// `validator` has authorized `sender` as its operator via
/// `ActionPayload::AuthorizeOperator` — never the other way around, and
/// never transitively.
pub(crate) fn is_authorized(
    sender: &Address,
    validator: &Address,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<bool> {
    if sender == validator {
        return Ok(true);
    }
    Ok(operator_lookup(validator)?.as_ref() == Some(sender))
}

pub(crate) fn join_validator(
    action: &ChainAction,
    view: &BlockView<'_>,
    validator: &Address,
    stake: u128,
    bls_pubkey: &[u8],
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    if !is_authorized(&action.sender, validator, operator_lookup)? {
        anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
    }
    // The floor is on total self-stake, not this call's delta — a
    // validator already at/above it topping up further shouldn't be
    // re-charged the whole minimum again.
    let existing_active = view
        .get(&StakeKey { master: &action.sender, validator })?
        .map(|a| a.active_amount)
        .unwrap_or(0);
    if existing_active + stake < MIN_VALIDATOR_STAKE {
        anyhow::bail!(
            "stake {stake} is below the minimum validator stake {MIN_VALIDATOR_STAKE}"
        );
    }
    let (accounts, stakes) = circuit_staking::apply_stake(
        view,
        &action.sender,
        action.nonce,
        validator,
        stake,
        current_height,
    )?;
    // Registered in the same block as the join, so the validator is
    // never in the set without the ability to vote.
    let bytes = validated_bls_pubkey(bls_pubkey)?;
    if let Some(owner) = bls_pubkey_owner_lookup(&BlsPublicKey(bytes))? {
        if &owner != validator {
            anyhow::bail!("BLS pubkey already registered to {owner}");
        }
    }
    // `bls_pubkey` here is informational, like `stake`:
    // `ValidatorSetSnapshot` persists neither, and the authoritative
    // registration is the `bls_key` update below.
    let change = ValidatorChange::Join(
        validator.clone(),
        ValidatorEntry { stake, bls_pubkey: Some(hex::encode(bytes)) },
    );
    Ok(BlockUpdates {
        accounts,
        stakes,
        validator_change: Some(change),
        bls_key: Some(BlsKeyRegistration {
            address: validator.clone(),
            pubkey: xc_bls::BlsPublicKey(bytes),
            // Same one-block delay as the `ValidatorSetSnapshot` this join
            // produces — the validator isn't eligible to vote until
            // `current_height + 1` either, so the key becomes valid then too.
            effective_height: current_height + 1,
        }),
        ..Default::default()
    })
}

pub(crate) fn leave_validator(
    action: &ChainAction,
    view: &BlockView<'_>,
    validator: &Address,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    if !is_authorized(&action.sender, validator, operator_lookup)? {
        anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
    }
    if !validators.contains(validator) {
        anyhow::bail!("{validator} is not a current validator");
    }
    if validators.len() <= 1 {
        anyhow::bail!("cannot remove the last validator, chain would stall forever");
    }
    // Whose funds actually move is never assumed to be `action.sender`
    // — it's whoever the storage-recorded master is
    // (`circuit_staking::apply_stake`'s single-master invariant),
    // resolved fresh here. `action.sender` only had to pass the
    // `is_authorized` check above; after an operator is revoked and
    // replaced, the *new* operator (or the validator itself) is
    // authorized to trigger leaving, but the stake still sits under
    // whichever address actually funded it — using `action.sender`
    // here would either find no allocation at all or, worse, silently
    // touch the wrong one.
    let master = view
        .get(&StakeByValidatorKey(validator))?
        .unwrap_or_default()
        .into_iter()
        .next()
        .unwrap_or_else(|| action.sender.clone());
    let self_stake = view
        .get(&StakeKey { master: &master, validator })?
        .ok_or_else(|| anyhow::anyhow!("{master} has no stake in {validator} to unstake"))?;
    // The master's own nonce, not `action.sender`'s — this action's
    // own replay protection already happened at admission (keyed on
    // `action.sender`'s nonce); `apply_unstake`'s nonce check is
    // master-account bookkeeping, meaningless against a different
    // account's counter when `master != action.sender`.
    let master_nonce = view.get(&AccountKey(&master))?.map(|entry| entry.nonce).unwrap_or(0);
    let (accounts, stakes) = circuit_staking::apply_unstake(
        view,
        &master,
        master_nonce,
        validator,
        self_stake.active_amount,
        current_height,
    )?;
    Ok(BlockUpdates {
        accounts,
        stakes,
        validator_change: Some(ValidatorChange::Leave(validator.clone())),
        ..Default::default()
    })
}

/// MW-signature-only stake into a validator's sub-account
/// (`circuit_staking::stake_subaccount`). See `circuit_staking::apply_stake`.
pub(crate) fn stake(
    view: &BlockView<'_>,
    action: &ChainAction,
    validator: &Address,
    amount: u128,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let (accounts, stakes) = circuit_staking::apply_stake(
        view,
        &action.sender,
        action.nonce,
        validator,
        amount,
        current_height,
    )?;
    Ok(BlockUpdates { accounts, stakes, ..Default::default() })
}

/// MW-signature-only partial or full unstake, subject to
/// `circuit_staking::UNBONDING_BLOCKS`. See `circuit_staking::apply_unstake`.
/// There is deliberately no `Slash` variant — slashing is never
/// user-submitted, so it's unreachable from RPC/mempool by construction
/// (see `circuit_staking::apply_slash`).
pub(crate) fn unstake(
    view: &BlockView<'_>,
    action: &ChainAction,
    validator: &Address,
    amount: u128,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let (accounts, stakes) = circuit_staking::apply_unstake(
        view,
        &action.sender,
        action.nonce,
        validator,
        amount,
        current_height,
    )?;
    Ok(BlockUpdates { accounts, stakes, ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{ACTION_FEE, ActionPayload};
    use std::collections::HashMap;
    use xc_primitives::{Action, StakeAllocation};
    use xc_storage::StorageError;

    #[test]
    fn leave_validator_rejected_when_sender_is_the_last_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::new(), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice.clone() },
        };

        let err = match crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected leaving the last validator to be rejected"),
        };
        assert!(err.to_string().contains("last validator"));
    }

    #[test]
    fn leave_validator_succeeds_when_others_remain() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::from([((alice.clone(), alice.clone()), self_allocation(&alice, 2_000))]),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice.clone() },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice.clone(), bob],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();
        assert!(matches!(updates.validator_change, Some(ValidatorChange::Leave(a)) if a == alice));
    }

    #[test]
    fn join_validator_debits_sender_and_credits_own_subaccount() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(MIN_VALIDATOR_STAKE + 2_000_000))]),
            HashMap::new(),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Join(ref a, _)) if *a == alice)
        );
        assert_eq!(
            updates.accounts.0.get(&alice).unwrap().balance,
            2_000_000 - ACTION_FEE
        );
        let sub = circuit_staking::stake_subaccount(&alice);
        assert_eq!(
            updates.accounts.0.get(&sub).unwrap().balance,
            MIN_VALIDATOR_STAKE
        );
        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(allocation.active_amount, MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn second_join_tops_up_rather_than_double_charging() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(2_000_000))]),
            HashMap::from([(
                (alice.clone(), alice.clone()),
                self_allocation(&alice, MIN_VALIDATOR_STAKE),
            )]),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: 500,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice.clone()],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();

        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            allocation.active_amount,
            MIN_VALIDATOR_STAKE + 500,
            "top-up adds to the existing self-stake"
        );
    }

    #[test]
    fn join_validator_rejected_with_insufficient_balance() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(100))]), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance")
                || err.to_string().contains("InsufficientBalance")
        );
    }

    #[test]
    fn join_validator_rejected_below_minimum_stake() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(10_000))]), HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: MIN_VALIDATOR_STAKE - 1,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("minimum validator stake"));
    }

    #[test]
    fn leave_validator_starts_unbonding_rather_than_instant_return() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(ACTION_FEE))]),
            HashMap::from([(
                (alice.clone(), alice.clone()),
                self_allocation(&alice, MIN_VALIDATOR_STAKE),
            )]),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice.clone() },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice.clone(), bob],
            5,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Leave(ref a)) if *a == alice)
        );
        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice.clone()))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            allocation.active_amount, 0,
            "full self-stake moves out of active"
        );
        let unbonding = allocation
            .unbonding
            .expect("leaving must start an unbonding batch, not an instant refund");
        assert_eq!(unbonding.amount, MIN_VALIDATOR_STAKE);
        assert_eq!(
            unbonding.unlock_at_height,
            5 + circuit_staking::UNBONDING_BLOCKS
        );
        // No balance credited back yet — still sitting in the sub-account, slashable.
        assert_eq!(
            updates
                .accounts
                .0
                .get(&alice)
                .map(|a| a.balance)
                .unwrap_or(0),
            0
        );
    }

    #[test]
    fn leave_validator_rejected_while_already_unbonding() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        // Active portion left nonzero (e.g. a prior manual partial Unstake)
        // so the `amount == 0` guard in apply_unstake doesn't fire first —
        // this test is specifically about the AlreadyUnbonding rejection.
        let mut allocation = self_allocation(&alice, 300);
        allocation.unbonding = Some(xc_primitives::Unbonding {
            amount: 700,
            unlock_at_height: 100,
        });
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::new(),
            HashMap::from([((alice.clone(), alice.clone()), allocation)]),
        );
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice.clone() },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice.clone(), bob],
            5,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already has an unbonding batch"));
    }

    #[test]
    fn join_validator_rejected_when_sender_not_authorized_for_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(bob.clone(), funded(5_000))]), HashMap::new());
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not authorized to manage"));
    }

    #[test]
    fn authorized_operator_can_join_validator_on_behalf_of_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(bob.clone(), funded(MIN_VALIDATOR_STAKE + 2_000_000))]),
            HashMap::new(),
        );
        let operator_lookup = make_operator_lookup(HashMap::from([(alice.clone(), bob.clone())]));
        let action = Action {
            sender: bob.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Join(ref a, _)) if *a == alice)
        );
        // The operator's own balance funds a delegated join, same as a
        // third-party `Stake` action would.
        assert_eq!(
            updates.accounts.0.get(&bob).unwrap().balance,
            2_000_000 - ACTION_FEE
        );
        let allocation = updates
            .stakes
            .allocations
            .get(&(bob, alice))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(allocation.active_amount, MIN_VALIDATOR_STAKE);
    }

    /// Regression test for a fund-lock found in review: operator A stakes
    /// for validator V, V revokes A and authorizes B instead — B (now
    /// authorized to trigger leaving) must not be assumed to be the funder.
    /// The unstake has to resolve to A's actual allocation via the
    /// `StakeByValidatorKey` index, not `(action.sender, validator)`, or the
    /// stake becomes permanently unreachable (no code path ever finds it
    /// again).
    #[test]
    fn leave_validator_after_operator_revoked_and_replaced_still_credits_the_true_funder() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap(); // validator
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap(); // revoked ex-operator, real funder
        let charlie = Address::from_pubkey_bytes(&[3u8; 32]).unwrap(); // newly authorized operator

        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(charlie.clone(), funded(ACTION_FEE))]),
            HashMap::from([(
                (bob.clone(), alice.clone()),
                StakeAllocation {
                    master: bob.clone(),
                    validator: alice.clone(),
                    active_amount: MIN_VALIDATOR_STAKE,
                    unbonding: None,
                    created_at: 0,
                    updated_at: 0,
                },
            )]),
        );
        view.put(&StakeByValidatorKey(&alice), &vec![bob.clone()]).unwrap();
        // Current state after revoke-then-reauthorize: charlie, not bob, is
        // now alice's authorized operator.
        let operator_lookup = make_operator_lookup(HashMap::from([(alice.clone(), charlie.clone())]));

        let action = Action {
            sender: charlie.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice.clone() },
        };

        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[alice.clone(), bob.clone()],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap();

        assert!(matches!(updates.validator_change, Some(ValidatorChange::Leave(ref a)) if *a == alice));
        let allocation = updates
            .stakes
            .allocations
            .get(&(bob, alice))
            .unwrap()
            .clone()
            .unwrap();
        assert!(allocation.unbonding.is_some(), "unstake must land on the real funder's allocation");
        assert_eq!(allocation.active_amount, 0);
    }

    #[test]
    fn revoked_operator_can_no_longer_join_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(bob.clone(), funded(5_000))]), HashMap::new());
        // No entry for alice: same state as after a `RevokeOperator`.
        let operator_lookup = make_operator_lookup(HashMap::new());
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not authorized to manage"));
    }

    /// A validator that cannot vote must not be able to join. Every validator
    /// counts toward the finality quorum whether or not it holds a BLS key, so
    /// one without a key raises the threshold while contributing nothing
    /// toward meeting it — enough of them and the chain finalizes nothing.
    /// This is Cosmos's `MsgCreateValidator.pubkey` being a required field.
    #[test]
    fn joining_with_an_invalid_bls_key_is_rejected() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(MIN_VALIDATOR_STAKE + 2_000_000))]),
            HashMap::new(),
        );

        for (label, pubkey) in [
            ("empty", Vec::new()),
            ("wrong length", vec![0u8; 32]),
            ("right length, off curve", vec![0xAAu8; 48]),
        ] {
            let action = Action {
                sender: alice.clone(),
                nonce: 0,
                signature: None,
                payload: ActionPayload::JoinValidator {
                    validator: alice.clone(),
                    stake: MIN_VALIDATOR_STAKE,
                    bls_pubkey: pubkey,
                },
            };
            let result = crate::dispatch(
                &action,
                &view,
                &operator_lookup,
                &operator_validators_lookup,
                &[],
                10,
                &|_, _| Ok::<bool, StorageError>(false),
                &no_bls_owner,
            );
            assert!(
                result.is_err(),
                "a {label} BLS key must not get a validator into the set",
            );
        }
    }

    /// The join and the key registration land in the same block, so a
    /// validator is never in the set without the means to vote — no window,
    /// however brief, and no chance of a second step never happening.
    #[test]
    fn joining_registers_the_bls_key_in_the_same_block() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(MIN_VALIDATOR_STAKE + 2_000_000))]),
            HashMap::new(),
        );
        let pubkey = test_bls_pubkey(42);

        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice.clone(),
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: pubkey.clone(),
            },
        };
        let updates = crate::dispatch(
            &action,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
            &no_bls_owner,
        )
        .expect("a well-formed join must succeed");

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Join(ref a, _)) if *a == alice),
            "the join itself must still be applied",
        );
        let registration = updates
            .bls_key
            .expect("the BLS key must be registered by the same action");
        assert_eq!(registration.address, alice);
        assert_eq!(
            registration.pubkey.0.to_vec(),
            pubkey,
            "the registered key must be the one the action carried",
        );
    }
}
