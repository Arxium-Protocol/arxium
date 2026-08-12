use serde::{Deserialize, Serialize};
use xc_primitives::{AccountEntry, Action, Address, ValidatorChange, ValidatorEntry};
use xc_storage::{AccountUpdates, StorageError};

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
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

/// The payload → circuit mapping `xc_executor::execute_actions` calls per
/// action. This is the only place CoreChain decides what a payload variant
/// means. `validators` is the set as of the start of this block — the same
/// one `accept_block`/`produce_block` will fold this action's
/// `ValidatorChange` onto.
pub fn dispatch(
    action: &ChainAction,
    lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    validators: &[Address],
) -> anyhow::Result<(AccountUpdates, Option<ValidatorChange>)> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => Ok((
            circuit_account::apply_transfer(lookup, &action.sender, action.nonce, to, *amount)?,
            None,
        )),
        ActionPayload::JoinValidator { stake } => {
            let change = ValidatorChange::Join(action.sender.clone(), ValidatorEntry { stake: *stake });
            Ok((AccountUpdates(Default::default()), Some(change)))
        }
        ActionPayload::LeaveValidator => {
            if !validators.contains(&action.sender) {
                anyhow::bail!("{} is not a current validator", action.sender);
            }
            if validators.len() <= 1 {
                anyhow::bail!("cannot remove the last validator, chain would stall forever");
            }
            Ok((
                AccountUpdates(Default::default()),
                Some(ValidatorChange::Leave(action.sender.clone())),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(_addr: &Address) -> Result<Option<AccountEntry>, StorageError> {
        Ok(None)
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

        let err = match dispatch(&action, &lookup, &[alice]) {
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

        let (_, change) = dispatch(&action, &lookup, &[alice.clone(), bob]).unwrap();
        assert!(matches!(change, Some(ValidatorChange::Leave(a)) if a == alice));
    }
}
