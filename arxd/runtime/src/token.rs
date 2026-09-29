// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Runtime glue for `ActionPayload::Token` → `circuit_token`. Tokens live in
//! the asset ledger, so every handler writes the mutated record back through
//! `asset_registration` (an upsert — see `asset::issue_asset`).

use xc_circuit::{AssetKey, ChainParamsKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Asset, AssetClass, AssetMetadata, AssetRef};
use xc_storage::StorageError;

use crate::{ChainAction, TokenAction};

pub(crate) fn dispatch<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    token_action: &TokenAction,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let sender = &action.sender;
    let (accounts, assets, record) = match token_action {
        TokenAction::Create {
            symbol,
            name,
            decimals,
            initial_supply,
            max_supply,
            mintable,
        } => {
            let metadata = AssetMetadata {
                asset_class: AssetClass::Token,
                decimals: *decimals,
                max_supply: *max_supply,
                symbol: symbol.clone(),
                name: name.clone(),
                ..Default::default()
            };
            crate::asset::validate_metadata(&metadata)?;
            // A validated symbol is `[A-Z0-9]+`, so its lowercase is a valid
            // asset id: one token per ticker per creator.
            let asset_id = symbol.to_lowercase();
            let asset_ref = AssetRef::derive(sender, &asset_id)?;
            if view.get(&AssetKey(&asset_ref))?.is_some() {
                anyhow::bail!("{sender} already has an asset with id {asset_id} ({asset_ref})");
            }
            let mut token = Asset::register(
                asset_ref,
                asset_id,
                sender.clone(),
                false,
                metadata,
                current_height,
            );
            token.issuance_locked = !mintable;
            let fee = view
                .get(&ChainParamsKey)?
                .unwrap_or_default()
                .token_create_fee;
            let (accounts, assets) =
                circuit_token::apply_create(view, &mut token, *initial_supply, fee)?;
            (accounts, assets, token)
        }
        TokenAction::Mint { token, to, amount } => {
            let mut token = resolve(view, token)?;
            let assets = circuit_token::apply_mint(view, &mut token, sender, to, *amount)?;
            (Default::default(), assets, token)
        }
        TokenAction::Transfer { token, to, amount } => {
            let mut token = resolve(view, token)?;
            let assets = circuit_token::apply_transfer(view, &mut token, sender, to, *amount)?;
            (Default::default(), assets, token)
        }
        TokenAction::Burn { token, amount } => {
            let mut token = resolve(view, token)?;
            let assets = circuit_token::apply_burn(view, &mut token, sender, *amount)?;
            (Default::default(), assets, token)
        }
        TokenAction::RenounceMint { token } => {
            let mut token = resolve(view, token)?;
            circuit_token::apply_renounce_mint(&mut token, sender)?;
            (Default::default(), Default::default(), token)
        }
    };
    Ok(BlockUpdates {
        accounts,
        assets,
        asset_registration: Some(record),
        ..Default::default()
    })
}

/// The circuit re-checks the class; this only turns "missing" into a clean
/// rejection.
fn resolve<V: KvRead<Error = StorageError>>(view: &V, token: &AssetRef) -> anyhow::Result<Asset> {
    view.get(&AssetKey(token))?
        .ok_or_else(|| anyhow::anyhow!("unknown token {token}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionPayload;
    use crate::test_support::*;
    use std::collections::HashMap;
    use xc_circuit::{AccountKey, AssetBalanceKey};
    use xc_primitives::{Action, Address, ChainParams, treasury_account};
    use xc_storage::BlockView;

    fn run(
        view: &BlockView<'_>,
        sender: &Address,
        nonce: u64,
        payload: ActionPayload,
    ) -> anyhow::Result<BlockUpdates> {
        crate::dispatch(
            &Action {
                sender: sender.clone(),
                nonce,
                signature: None,
                payload,
            },
            view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            0,
            &no_bls_owner,
            0,
        )
    }

    fn commit(view: &mut BlockView<'_>, updates: &BlockUpdates) {
        view.apply_accounts(&updates.accounts).unwrap();
        view.apply_asset_balances(&updates.assets).unwrap();
        if let Some(asset) = &updates.asset_registration {
            view.apply_asset_registration(asset).unwrap();
        }
    }

    fn create(mintable: bool) -> ActionPayload {
        ActionPayload::Token(TokenAction::Create {
            symbol: "ARXD".into(),
            name: "Arx Dollar".into(),
            decimals: 6,
            initial_supply: 1_000,
            max_supply: None,
            mintable,
        })
    }

    /// Create → transfer through the real dispatch: the creation fee lands in
    /// the treasury on top of the metered fee, nonces advance, and the token
    /// is refused by every regulated handler.
    #[test]
    fn create_and_transfer_through_dispatch_and_rwa_path_refuses_tokens() {
        let (alice, bob) = (
            Address::from_pubkey_bytes(&[1u8; 32]).unwrap(),
            Address::from_pubkey_bytes(&[2u8; 32]).unwrap(),
        );
        let db = temp_db();
        let fee = ChainParams::default().token_create_fee;
        let start = fee + FEE_BUDGET * 4;
        let mut view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(start))]),
            HashMap::new(),
        );

        let created = run(&view, &alice, 0, create(true)).unwrap();
        let token = created.asset_registration.clone().unwrap();
        assert_eq!(token.asset_ref, AssetRef::derive(&alice, "arxd").unwrap());
        assert_eq!(created.accounts.0[&treasury_account()].balance, fee);
        let paid = start - created.accounts.0[&alice].balance;
        assert!(paid > fee, "creation fee plus the metered action fee");
        assert_eq!(created.accounts.0[&alice].nonce, 1);
        commit(&mut view, &created);

        // Same ticker again from the same creator is refused.
        assert!(run(&view, &alice, 1, create(true)).is_err());

        let moved = run(
            &view,
            &alice,
            1,
            ActionPayload::Token(TokenAction::Transfer {
                token: token.asset_ref.clone(),
                to: bob.clone(),
                amount: 400,
            }),
        )
        .unwrap();
        commit(&mut view, &moved);
        let balance = |who: &Address| {
            view.get(&AssetBalanceKey {
                asset: &token.asset_ref,
                owner: who,
            })
            .unwrap()
            .unwrap_or(0)
        };
        assert_eq!((balance(&alice), balance(&bob)), (600, 400));
        assert_eq!(view.get(&AccountKey(&alice)).unwrap().unwrap().nonce, 2);

        // The regulated path cannot touch it: no RWA transfer, no freeze,
        // and RegisterAsset cannot mint a Token-class record.
        assert!(
            run(
                &view,
                &alice,
                2,
                ActionPayload::TransferAsset {
                    asset: token.asset_ref.clone(),
                    to: bob.clone(),
                    amount: 1
                }
            )
            .is_err()
        );
        assert!(
            run(
                &view,
                &alice,
                2,
                ActionPayload::FreezeAsset {
                    asset: token.asset_ref.clone(),
                    reason: "no".into()
                }
            )
            .is_err()
        );
        assert!(
            run(
                &view,
                &alice,
                2,
                ActionPayload::RegisterAsset {
                    asset_id: "fake".into(),
                    compliance_required: false,
                    metadata: AssetMetadata {
                        asset_class: AssetClass::Token,
                        symbol: "FAKE".into(),
                        name: "Fake".into(),
                        ..Default::default()
                    },
                },
            )
            .is_err()
        );
    }

    #[test]
    fn create_without_the_fee_is_refused() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(FEE_BUDGET))]),
            HashMap::new(),
        );
        assert!(run(&view, &alice, 0, create(false)).is_err());
    }
}
