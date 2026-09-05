// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_circuit::KvRead;
use xc_executor::BlockUpdates;
use xc_primitives::Address;
use xc_storage::{OperatorUpdates, StorageError};

use crate::ChainAction;

pub(crate) fn transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    to: &Address,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    Ok(BlockUpdates {
        accounts: circuit_account::apply_transfer(view, &action.sender, action.nonce, to, amount)?,
        ..Default::default()
    })
}

pub(crate) fn authorize_operator(
    action: &ChainAction,
    operator: &Address,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    let validator = action.sender.clone();
    let mut operator_index = std::collections::BTreeMap::new();
    if let Some(previous) = operator_lookup(&validator)? {
        if &previous != operator {
            let mut previous_list = operator_validators_lookup(&previous)?;
            previous_list.retain(|v| v != &validator);
            operator_index.insert(previous, previous_list);
        }
    }
    let mut new_list = operator_validators_lookup(operator)?;
    if !new_list.contains(&validator) {
        new_list.push(validator.clone());
    }
    operator_index.insert(operator.clone(), new_list);

    let mut authorization = std::collections::BTreeMap::new();
    authorization.insert(validator, Some(operator.clone()));

    Ok(BlockUpdates {
        operator: OperatorUpdates { authorization, operator_index },
        ..Default::default()
    })
}

pub(crate) fn revoke_operator(
    action: &ChainAction,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    let validator = action.sender.clone();
    let previous = operator_lookup(&validator)?
        .ok_or_else(|| anyhow::anyhow!("{validator} has no authorized operator to revoke"))?;

    let mut list = operator_validators_lookup(&previous)?;
    list.retain(|v| v != &validator);
    let mut operator_index = std::collections::BTreeMap::new();
    operator_index.insert(previous, list);

    let mut authorization = std::collections::BTreeMap::new();
    authorization.insert(validator, None);

    Ok(BlockUpdates {
        operator: OperatorUpdates { authorization, operator_index },
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{ACTION_FEE, ActionPayload};
    use std::collections::HashMap;
    use xc_primitives::Action;

    #[test]
    fn authorize_operator_then_revoke_updates_forward_and_reverse_index() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(alice.clone(), funded(2 * ACTION_FEE))]), HashMap::new());
        let authorize = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::AuthorizeOperator { operator: bob.clone() },
        };

        let updates = crate::dispatch(
            &authorize,
            &view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            10,
            &no_bls_owner,
        )
        .unwrap();
        assert_eq!(
            updates.operator.authorization.get(&alice).cloned().flatten(),
            Some(bob.clone())
        );
        assert_eq!(
            updates.operator.operator_index.get(&bob).cloned().unwrap_or_default(),
            vec![alice.clone()]
        );

        // Once authorized, revoking must be reflected in the same two places
        // — forward record cleared, reverse index no longer lists alice.
        let operator_lookup_after = make_operator_lookup(HashMap::from([(alice.clone(), bob.clone())]));
        let alice_for_closure = alice.clone();
        let bob_for_closure = bob.clone();
        let operator_validators_lookup_after = move |op: &Address| {
            Ok(if *op == bob_for_closure { vec![alice_for_closure.clone()] } else { Vec::new() })
        };
        let revoke = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RevokeOperator,
        };
        let updates = crate::dispatch(
            &revoke,
            &view,
            &operator_lookup_after,
            &operator_validators_lookup_after,
            &[],
            10,
            &no_bls_owner,
        )
        .unwrap();
        assert_eq!(updates.operator.authorization.get(&alice).cloned(), Some(None));
        assert!(
            updates
                .operator
                .operator_index
                .values()
                .all(|validators| !validators.contains(&alice))
        );
    }
}
