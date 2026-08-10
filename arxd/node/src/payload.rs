use serde::{Deserialize, Serialize};
use xc_primitives::{AccountEntry, Action, Address};
use xc_storage::{AccountUpdates, StorageError};

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer { to: Address, amount: u128 },
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

/// The payload → circuit mapping `xc_executor::execute_actions` calls per
/// action. This is the only place CoreChain decides what a payload variant
/// means.
pub fn dispatch(
    action: &ChainAction,
    lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
) -> anyhow::Result<AccountUpdates> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => Ok(circuit_account::apply_transfer(
            lookup,
            &action.sender,
            action.nonce,
            to,
            *amount,
        )?),
    }
}
