use serde::{Deserialize, Serialize};
use xc_executor::BlockUpdates;
use xc_primitives::{AccountEntry, Action, Address, StakeAllocation, ValidatorChange, ValidatorEntry};
use xc_storage::StorageError;

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer { to: Address, amount: u128 },
    /// Self-service: the sender becomes a round-robin validator, effective
    /// one block after this action lands (`xc_executor::accept_block`'s
    /// effective-height rule) — can't vote itself into this block's own
    /// proposer slot. `stake` is bookkeeping only for now; round-robin
    /// selection ignores it (`xc_primitives::expected_proposer`).
    JoinValidator { stake: u128 },
    /// Self-service removal. Rejected if the sender isn't currently a
    /// validator, or if they're the last one — an empty validator set means
    /// `expected_proposer` returns `None` forever and the chain can never
    /// produce another block (the same deadlock hit live this session from
    /// running `--bootnode` on two machines, self-inflicted here instead).
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
            let change = ValidatorChange::Join(action.sender.clone(), ValidatorEntry { stake: *stake });
            Ok(BlockUpdates { validator_change: Some(change), ..Default::default() })
        }
        ActionPayload::LeaveValidator => {
            if !validators.contains(&action.sender) {
                anyhow::bail!("{} is not a current validator", action.sender);
            }
            if validators.len() <= 1 {
                anyhow::bail!("cannot remove the last validator, chain would stall forever");
            }
            Ok(BlockUpdates {
                validator_change: Some(ValidatorChange::Leave(action.sender.clone())),
                ..Default::default()
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

    fn lookup(_addr: &Address) -> Result<Option<AccountEntry>, StorageError> {
        Ok(None)
    }

    fn stake_lookup(_master: &Address, _validator: &Address) -> Result<Option<StakeAllocation>, StorageError> {
        Ok(None)
    }

    fn validator_masters_lookup(_validator: &Address) -> Result<Vec<Address>, StorageError> {
        Ok(Vec::new())
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
}
