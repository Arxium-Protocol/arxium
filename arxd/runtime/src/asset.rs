// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_circuit::{AssetKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Address, Asset};
use xc_storage::StorageError;

use crate::ChainAction;

pub(crate) fn register_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset_id: &str,
    compliance_required: bool,
) -> anyhow::Result<BlockUpdates> {
    if view.get(&AssetKey(asset_id))?.is_some() {
        anyhow::bail!("asset {asset_id} is already registered");
    }
    let asset = Asset {
        asset_id: asset_id.to_string(),
        issuer: action.sender.clone(),
        compliance_required,
    };
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

fn resolve_asset<V: KvRead<Error = StorageError>>(view: &V, asset_id: &str) -> anyhow::Result<Asset> {
    view.get(&AssetKey(asset_id))?
        .ok_or_else(|| anyhow::anyhow!("asset {asset_id} is not registered"))
}

pub(crate) fn issue_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset_id: &str,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let asset = resolve_asset(view, asset_id)?;
    let (accounts, assets) =
        circuit_rwa_asset::apply_issue(view, &asset, &action.sender, action.nonce, amount)?;
    Ok(BlockUpdates { accounts, assets, ..Default::default() })
}

pub(crate) fn transfer_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset_id: &str,
    to: &Address,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let asset = resolve_asset(view, asset_id)?;
    let (accounts, assets) = circuit_rwa_asset::apply_compliant_transfer(
        view,
        &asset,
        &action.sender,
        action.nonce,
        to,
        amount,
    )?;
    Ok(BlockUpdates { accounts, assets, ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::{ActionPayload, ACTION_FEE};
    use std::collections::HashMap;
    use xc_primitives::Action;
    use xc_storage::BlockView;

    #[test]
    fn transfer_asset_fails_without_recipient_attestation_and_succeeds_after_grant() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let recipient = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();

        let mut issuer_account = funded(ACTION_FEE * 4);
        issuer_account.identity_hash = Some("kyc-issuer".into());
        let mut view = seeded_view(
            &db,
            HashMap::from([(issuer.clone(), issuer_account)]),
            HashMap::new(),
        );

        fn dispatch(action: &ChainAction, view: &BlockView<'_>) -> anyhow::Result<BlockUpdates> {
            crate::dispatch(
                action,
                view,
                &operator_lookup,
                &operator_validators_lookup,
                &[],
                0,
                &no_bls_owner,
            )
        }

        let register = Action {
            sender: issuer.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterAsset { asset_id: "gold".into(), compliance_required: true },
        };
        let updates = dispatch(&register, &view).unwrap();
        let asset = updates.asset_registration.clone().expect("asset registered");
        view.put(&AssetKey("gold"), &asset).unwrap();
        view.apply_accounts(&updates.accounts).unwrap();

        // RegisterAsset doesn't touch the sender's account nonce, so the
        // issuer's nonce is still 0 here.
        let issue = Action {
            sender: issuer.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::IssueAsset { asset_id: "gold".into(), amount: 1000 },
        };
        let updates = dispatch(&issue, &view).unwrap();
        view.apply_accounts(&updates.accounts).unwrap();
        view.apply_asset_balances(&updates.assets).unwrap();

        // Recipient has no attestation yet — transfer must fail. The
        // compliance check runs before the nonce check, so the rejected
        // attempt doesn't consume nonce 1.
        let transfer = Action {
            sender: issuer.clone(),
            nonce: 1,
            signature: None,
            payload: ActionPayload::TransferAsset { asset_id: "gold".into(), to: recipient.clone(), amount: 100 },
        };
        let err = dispatch(&transfer, &view).unwrap_err();
        assert!(err.to_string().contains("not KYC'd"));

        // ponytail: this test's chain has no configured attestor, so grant
        // via a direct account write instead of round-tripping through
        // `GrantAttestation` dispatch — attestor authorization is covered
        // separately in `identity.rs`'s own tests.
        let mut recipient_account = funded(0);
        recipient_account.identity_hash = Some("kyc-recipient".into());
        view.put(&xc_circuit::AccountKey(&recipient), &recipient_account).unwrap();

        let transfer = Action {
            sender: issuer.clone(),
            nonce: 1,
            signature: None,
            payload: ActionPayload::TransferAsset { asset_id: "gold".into(), to: recipient.clone(), amount: 100 },
        };
        let updates = dispatch(&transfer, &view).unwrap();
        assert_eq!(updates.assets.0[&("gold".to_string(), recipient)], 100);
    }
}
