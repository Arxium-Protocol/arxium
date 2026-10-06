// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::{ActionPayload, ChainAction, TokenAction};
use xc_circuit::{AccountKey, AssetBalanceKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::*;
use xc_storage::StorageError;

fn transfer(action: &ChainAction) -> Option<(SpendAsset, &Address, u128)> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => Some((SpendAsset::Native, to, *amount)),
        ActionPayload::TransferAsset { asset, to, amount } => {
            Some((SpendAsset::Asset(asset.clone()), to, *amount))
        }
        ActionPayload::Token(TokenAction::Transfer { token, to, amount }) => {
            Some((SpendAsset::Asset(token.clone()), to, *amount))
        }
        _ => None,
    }
}

pub(crate) fn authorization<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    height: u64,
    genesis: &[u8; 32],
) -> anyhow::Result<PolicyAuthorization> {
    let extensions = view
        .get(&xc_circuit::ChainParamsKey)?
        .unwrap_or_default()
        .account_extensions_enabled;
    if !extensions
        && matches!(
            &action.payload,
            ActionPayload::AccountPolicy(
                AccountPolicyAction::AddSession { .. }
                    | AccountPolicyAction::StartRecovery { .. }
                    | AccountPolicyAction::ExecuteRecovery
            )
        )
    {
        anyhow::bail!("session keys and recovery are not activated");
    }
    if let ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy }) = &action.payload
    {
        policy.validate()?;
        if !extensions && (!policy.sessions.is_empty() || policy.recovery.is_some()) {
            anyhow::bail!("session keys and recovery are not activated");
        }
    }
    let account = view.get(&AccountKey(&action.sender))?.unwrap_or_default();
    // Legacy dispatch tests and handler callers supply unsigned actions; the
    // executor verifies legacy signatures. Stateful authorization is mandatory
    // here as well because it controls privileged payload scope.
    let Some(state) = account.programmable.as_ref() else {
        return Ok(PolicyAuthorization::Owner);
    };
    let auth = action.verify_account_signature(Some(state), genesis)?;
    if !extensions && auth != PolicyAuthorization::Owner {
        anyhow::bail!("session keys and recovery are not activated");
    }
    match auth {
        PolicyAuthorization::Guardian => {
            if !matches!(
                &action.payload,
                ActionPayload::AccountPolicy(
                    AccountPolicyAction::StartRecovery { .. }
                        | AccountPolicyAction::ExecuteRecovery
                )
            ) {
                anyhow::bail!("guardians can only start or execute recovery");
            }
        }
        PolicyAuthorization::Session(i) => {
            let session = &state.policy.sessions[i];
            let (asset, to, amount) =
                transfer(action).ok_or_else(|| anyhow::anyhow!("sessions are transfer-only"))?;
            if height >= session.expires_at
                || session.asset != asset
                || !session.recipients.contains(to)
                || amount > session.allowance
            {
                anyhow::bail!("session expired or transfer outside scope/allowance");
            }
        }
        PolicyAuthorization::Owner => {}
    }
    Ok(auth)
}

pub(crate) fn precheck<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    height: u64,
    genesis: &[u8; 32],
) -> anyhow::Result<()> {
    authorization(action, view, height, genesis)?;
    if let ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy }) = &action.payload
    {
        policy.validate()?;
    }
    Ok(())
}

pub(crate) fn apply<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    policy_action: &AccountPolicyAction,
    height: u64,
    genesis: &[u8; 32],
) -> anyhow::Result<BlockUpdates> {
    let auth = authorization(action, view, height, genesis)?;
    let mut entry = view.get(&AccountKey(&action.sender))?.unwrap_or_default();
    // Initial enrollment must be authorized by the existing key/immutable multisig.
    if entry.programmable.is_none() {
        action.verify_signature(genesis)?;
    }
    circuit_account::policy::apply_policy_action(&mut entry, policy_action, auth, height)?;
    let mut updates = BlockUpdates::default();
    updates.accounts.0.insert(action.sender.clone(), entry);
    Ok(updates)
}

pub(crate) fn enforce<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    height: u64,
    auth: PolicyAuthorization,
    updates: &mut BlockUpdates,
) -> anyhow::Result<()> {
    let before = view.get(&AccountKey(&action.sender))?.unwrap_or_default();
    let Some(mut state) = before.programmable.clone() else {
        return Ok(());
    };
    // Management cannot move funds apart from its ordinary metered fee. Owners
    // must still be able to rotate/revoke/cancel when a spending budget is zero
    // or exhausted; otherwise a valid zero limit permanently locks the account.
    // The policy circuit itself preserves counters for unchanged limits.
    if matches!(action.payload, ActionPayload::AccountPolicy(_)) {
        return Ok(());
    }
    let after = updates
        .accounts
        .0
        .get(&action.sender)
        .ok_or_else(|| anyhow::anyhow!("missing sender update"))?;
    let params = view.get(&xc_circuit::ChainParamsKey)?.unwrap_or_default();
    let fee = crate::metering::action_fee_for(&params, crate::metering::action_weight(action));
    let mut spends = vec![(
        SpendAsset::Native,
        before.balance.saturating_sub(after.balance).max(fee),
    )];
    let mut recipients = Vec::new();
    for (address, entry) in &updates.accounts.0 {
        if address != &action.sender
            && entry.balance > view.get(&AccountKey(address))?.unwrap_or_default().balance
        {
            recipients.push(address.clone());
        }
    }
    for ((asset, owner), balance) in &updates.assets.0 {
        let previous = view.get(&AssetBalanceKey { asset, owner })?.unwrap_or(0);
        if owner == &action.sender {
            spends.push((
                SpendAsset::Asset(asset.clone()),
                previous.saturating_sub(*balance),
            ));
        } else if *balance > previous {
            recipients.push(owner.clone());
        }
    }
    let transfer = transfer(action);
    // A self-transfer has no credited external row; still enforce its scope.
    if let Some((_, to, _)) = &transfer {
        recipients.push((*to).clone());
    }
    circuit_account::policy::enforce_spending(
        &mut state,
        auth,
        height,
        &spends,
        &recipients,
        transfer
            .as_ref()
            .map(|(asset, to, amount)| (asset, *to, *amount)),
    )?;
    let after = updates
        .accounts
        .0
        .get_mut(&action.sender)
        .expect("checked above");
    after.programmable = Some(state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use xc_storage::{AccountUpdates, ArxiumDb, BlockView};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn owners(keys: &[SigningKey], threshold: u8) -> ThresholdPolicy {
        let mut members = keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect::<Vec<_>>();
        members.sort();
        ThresholdPolicy { threshold, members }
    }
    fn policy(keys: &[SigningKey]) -> AccountPolicy {
        AccountPolicy {
            owners: owners(keys, 2),
            limits: vec![],
            recipients: None,
            sessions: vec![],
            recovery: None,
        }
    }
    fn signed(
        sender: &Address,
        nonce: u64,
        payload: ActionPayload,
        keys: &[SigningKey],
        mode: Option<u8>,
    ) -> ChainAction {
        let mut action = Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload,
        };
        let members = keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect::<Vec<_>>();
        let signatures = keys
            .iter()
            .take(2)
            .map(|k| {
                (
                    k.verifying_key().to_bytes(),
                    k.sign(&action.signing_bytes(&crate::TEST_GENESIS)).to_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let witness = multisig_signature(2, &members, &signatures).unwrap();
        action.signature = Some(match mode {
            Some(m) => policy_signature(m, &witness).unwrap(),
            None => witness,
        });
        action
    }
    fn run(
        view: &mut BlockView<'_>,
        action: &ChainAction,
        height: u64,
    ) -> anyhow::Result<BlockUpdates> {
        let account = view.get(&AccountKey(&action.sender))?;
        action.verify_account_signature(
            account.as_ref().and_then(|e| e.programmable.as_ref()),
            &crate::TEST_GENESIS,
        )?;
        let updates = crate::dispatch(
            action,
            view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            height,
            &no_bls_owner,
            0, &crate::TEST_GENESIS,
        )?;
        view.apply_accounts(&updates.accounts)?;
        view.apply_asset_balances(&updates.assets)?;
        if let Some(asset) = &updates.asset_registration {
            view.apply_asset_registration(asset)?;
        }
        Ok(updates)
    }
    fn funded_view<'a>(db: &'a ArxiumDb, sender: &Address) -> BlockView<'a> {
        let mut view = BlockView::new(db);
        view.put(&AccountKey(sender), &funded(100 * FEE_BUDGET))
            .unwrap();
        view
    }

    #[test]
    fn threshold_issuer_and_attestor_admin_execute_in_the_real_executor() {
        let db = temp_db();
        db.write_batch(&xc_storage::GenesisHash(hex::encode(crate::TEST_GENESIS))).unwrap();
        let keys = [key(7), key(8), key(9)];
        let issuer = multisig_address(2, &owners(&keys, 2).members).unwrap();
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            issuer.clone(),
            funded(100 * FEE_BUDGET),
        )]))])
        .unwrap();
        let mut admins = xc_storage::GovernanceUpdates::default();
        admins
            .put(
                &xc_circuit::AdminKey(xc_circuit::AdminRole::Attestor),
                &issuer,
            )
            .unwrap();
        db.write_batches(&[&admins]).unwrap();
        let asset = AssetRef::derive(&issuer, "gold").unwrap();
        let receiver = Address::from_pubkey_bytes(&key(10).verifying_key().to_bytes()).unwrap();
        let actions = vec![
            signed(
                &issuer,
                0,
                ActionPayload::RegisterAsset {
                    asset_id: "gold".into(),
                    compliance_required: false,
                    metadata: AssetMetadata {
                        symbol: "GOLD".into(),
                        name: "Gold".into(),
                        ..Default::default()
                    },
                },
                &keys,
                None,
            ),
            signed(
                &issuer,
                1,
                ActionPayload::IssueAsset {
                    asset: asset.clone(),
                    amount: 100,
                },
                &keys,
                None,
            ),
            signed(
                &issuer,
                2,
                ActionPayload::RegisterAttestor {
                    attestor: receiver.clone(),
                    name: "Provider".into(),
                    reason: "appointed".into(),
                },
                &keys,
                None,
            ),
            signed(
                &issuer,
                3,
                ActionPayload::IssuerForcedTransfer {
                    asset: asset.clone(),
                    from: issuer.clone(),
                    to: receiver.clone(),
                    amount: 20,
                    reason: "order".into(),
                },
                &keys,
                None,
            ),
            signed(
                &issuer,
                4,
                ActionPayload::FreezeAsset {
                    asset: asset.clone(),
                    reason: "halt".into(),
                },
                &keys,
                None,
            ),
        ];
        let outcome = xc_executor::execute_actions(
            &db,
            actions,
            &[],
            BlockUpdates::default(),
            |a, v, op, ops, validators| {
                crate::dispatch(a, v, op, ops, validators, 1, &no_bls_owner, 0, &crate::TEST_GENESIS)
            },
            &|a| (crate::metering::action_weight(a), fee_of(a)),
            None,
            true,
        )
        .unwrap();
        assert_eq!(outcome.applied.len(), 5, "{:?}", outcome.dropped);
        assert_eq!(outcome.accounts.0[&issuer].nonce, 5);
        assert!(
            outcome
                .touched_keys
                .iter()
                .any(|k| k == &xc_circuit::KeySpec::encode(&AccountKey(&issuer)))
        );
        // Below threshold fails before any role dispatch.
        let mut bad = signed(
            &issuer,
            5,
            ActionPayload::IssueAsset { asset, amount: 1 },
            &keys,
            None,
        );
        let witness = multisig_signature(
            2,
            &owners(&keys, 2).members,
            &[(
                keys[0].verifying_key().to_bytes(),
                keys[0].sign(&bad.signing_bytes(&crate::TEST_GENESIS)).to_bytes(),
            )],
        )
        .unwrap();
        bad.signature = Some(witness);
        assert!(bad.verify_signature(&crate::TEST_GENESIS).is_err());
    }

    /// "Offer both" (Trello #221): an institution that co-signs a holder's
    /// account makes regulated transfers stricter than the asset's own gate.
    /// Two recipients pass the asset's KYC rule, yet the account's allowlist
    /// refuses one; the holder's key alone can neither move units nor drop
    /// the allowlist; and the asset gate still refuses an allowlisted but
    /// un-attested recipient, so the chain's minimum holds underneath.
    #[test]
    fn institution_cosigned_account_is_stricter_than_the_asset_gate() {
        let db = temp_db();
        let keys = [key(1), key(2)]; // holder, institution
        let holder = multisig_address(2, &owners(&keys, 2).members).unwrap();
        let mut view = funded_view(&db, &holder);
        let addr =
            |seed| Address::from_pubkey_bytes(&key(seed).verifying_key().to_bytes()).unwrap();
        let (approved, other, unattested) = (addr(3), addr(4), addr(5));
        let kyc = |balance| AccountEntry {
            identity_hash: Some("kyc".into()),
            ..funded(balance)
        };
        view.put(&AccountKey(&holder), &kyc(100 * FEE_BUDGET))
            .unwrap();
        view.put(&AccountKey(&approved), &kyc(0)).unwrap();
        view.put(&AccountKey(&other), &kyc(0)).unwrap();
        let bond = Asset::new("bond", addr(9), true);
        let asset = bond.asset_ref.clone();
        view.put(&xc_circuit::AssetKey(&asset), &bond).unwrap();
        view.put(
            &AssetBalanceKey {
                asset: &asset,
                owner: &holder,
            },
            &100u128,
        )
        .unwrap();

        let mut p = policy(&keys);
        p.recipients = Some(vec![approved.clone(), unattested.clone()]);
        let enroll = ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy: p });
        run(&mut view, &signed(&holder, 0, enroll, &keys, None), 1).unwrap();

        let send = |to: &Address| ActionPayload::TransferAsset {
            asset: asset.clone(),
            to: to.clone(),
            amount: 10,
        };
        let err = run(
            &mut view,
            &signed(&holder, 1, send(&other), &keys, Some(0)),
            2,
        )
        .unwrap_err();
        assert!(err.to_string().contains("recipient"), "got: {err}");

        // The holder alone: one of two signatures, for a transfer or for
        // replacing the policy with one that has no allowlist.
        for payload in [
            send(&approved),
            ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy {
                policy: policy(&keys),
            }),
        ] {
            let mut alone = signed(&holder, 1, payload, &keys, Some(0));
            let witness = multisig_signature(
                2,
                &owners(&keys, 2).members,
                &[(
                    keys[0].verifying_key().to_bytes(),
                    keys[0].sign(&alone.signing_bytes(&crate::TEST_GENESIS)).to_bytes(),
                )],
            )
            .unwrap();
            alone.signature = Some(policy_signature(0, &witness).unwrap());
            let err = run(&mut view, &alone, 2).unwrap_err();
            assert!(err.to_string().contains("multisig witness"), "got: {err}");
        }

        let err = run(
            &mut view,
            &signed(&holder, 1, send(&unattested), &keys, Some(0)),
            2,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not KYC'd"), "got: {err}");

        run(
            &mut view,
            &signed(&holder, 1, send(&approved), &keys, Some(0)),
            2,
        )
        .unwrap();
        let balance = |owner| {
            view.get(&AssetBalanceKey {
                asset: &asset,
                owner,
            })
            .unwrap()
        };
        assert_eq!(balance(&holder), Some(90));
        assert_eq!(balance(&approved), Some(10));
    }

    #[test]
    fn rotation_retains_address_and_invalidates_old_keys_in_same_block() {
        let db = temp_db();
        let keys = [key(1), key(2), key(3)];
        let new = [key(4), key(5), key(6)];
        let sender = multisig_address(2, &owners(&keys, 2).members).unwrap();
        let mut view = funded_view(&db, &sender);
        run(
            &mut view,
            &signed(
                &sender,
                0,
                ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy {
                    policy: policy(&keys),
                }),
                &keys,
                None,
            ),
            1,
        )
        .unwrap();
        run(
            &mut view,
            &signed(
                &sender,
                1,
                ActionPayload::AccountPolicy(AccountPolicyAction::RotateMembers {
                    owners: owners(&new, 2),
                }),
                &keys,
                Some(0),
            ),
            1,
        )
        .unwrap();
        let transfer = ActionPayload::Transfer {
            to: sender.clone(),
            amount: 1,
        };
        assert!(
            run(
                &mut view,
                &signed(&sender, 2, transfer.clone(), &keys, Some(0)),
                1
            )
            .is_err()
        );
        assert!(
            run(
                &mut view,
                &signed(&sender, 2, transfer.clone(), &keys, None),
                1
            )
            .is_err()
        );
        run(&mut view, &signed(&sender, 2, transfer, &new, Some(0)), 1).unwrap();
        assert_eq!(view.get(&AccountKey(&sender)).unwrap().unwrap().nonce, 3);
    }

    #[test]
    fn limits_include_fees_accumulate_and_reset_only_at_block_boundaries() {
        let db = temp_db();
        let keys = [key(1), key(2), key(3)];
        let sender = multisig_address(2, &owners(&keys, 2).members).unwrap();
        let to = Address::from_pubkey_bytes(&key(4).verifying_key().to_bytes()).unwrap();
        let mut view = funded_view(&db, &sender);
        let tx = signed(
            &sender,
            1,
            ActionPayload::Transfer {
                to: to.clone(),
                amount: 100,
            },
            &keys,
            Some(0),
        );
        let mut uppercase = tx.clone();
        uppercase.signature = uppercase.signature.map(|s| s.to_uppercase());
        assert_eq!(
            fee_of(&uppercase),
            fee_of(&tx),
            "witness casing must not evade stored-policy metering"
        );
        let mut p = policy(&keys);
        p.recipients = Some(vec![to.clone()]);
        p.limits.push(SpendingLimit {
            asset: SpendAsset::Native,
            amount: 100 + fee_of(&tx),
            period_blocks: 10,
        });
        run(
            &mut view,
            &signed(
                &sender,
                0,
                ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy: p }),
                &keys,
                None,
            ),
            1,
        )
        .unwrap();
        run(&mut view, &tx, 1).unwrap();
        let unchanged = view
            .get(&AccountKey(&sender))
            .unwrap()
            .unwrap()
            .programmable
            .unwrap()
            .policy;
        run(
            &mut view,
            &signed(
                &sender,
                2,
                ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy: unchanged }),
                &keys,
                Some(0),
            ),
            1,
        )
        .unwrap();
        let again = signed(&sender, 3, tx.payload.clone(), &keys, Some(0));
        assert!(
            run(&mut view, &again, 9)
                .unwrap_err()
                .to_string()
                .contains("spending limit")
        );
        assert_eq!(view.get(&AccountKey(&sender)).unwrap().unwrap().nonce, 3);
        run(&mut view, &again, 10).unwrap();
        let wrong = signed(
            &sender,
            4,
            ActionPayload::Transfer {
                to: sender.clone(),
                amount: 1,
            },
            &keys,
            Some(0),
        );
        assert!(
            run(&mut view, &wrong, 20)
                .unwrap_err()
                .to_string()
                .contains("recipient")
        );
    }

    #[test]
    fn sessions_and_recovery_are_disabled_at_launch_and_scoped_after_activation() {
        let db = temp_db();
        let keys = [key(1), key(2), key(3)];
        let guardians = [key(7), key(8), key(9)];
        let new = [key(10), key(11), key(12)];
        let session_key = key(6);
        let sender = multisig_address(2, &owners(&keys, 2).members).unwrap();
        let to = Address::from_pubkey_bytes(&key(4).verifying_key().to_bytes()).unwrap();
        let mut view = funded_view(&db, &sender);
        let mut p = policy(&keys);
        p.sessions.push(SessionKey {
            public_key: session_key.verifying_key().to_bytes(),
            expires_at: 20,
            asset: SpendAsset::Native,
            allowance: 10,
            recipients: vec![to.clone()],
        });
        p.limits.push(SpendingLimit {
            asset: SpendAsset::Native,
            period_blocks: 10,
            amount: FEE_BUDGET,
        });
        p.recovery = Some(RecoveryPolicy {
            guardians: owners(&guardians, 2),
            delay_blocks: 5,
        });
        let enroll = signed(
            &sender,
            0,
            ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy: p }),
            &keys,
            None,
        );
        assert!(
            run(&mut view, &enroll, 1)
                .unwrap_err()
                .to_string()
                .contains("not activated")
        );
        view.put(
            &xc_circuit::ChainParamsKey,
            &ChainParams {
                account_extensions_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        run(&mut view, &enroll, 1).unwrap();
        let mut tx = Action {
            sender: sender.clone(),
            nonce: 1,
            signature: None,
            payload: ActionPayload::Transfer { to, amount: 10 },
        };
        let mut witness = session_key.verifying_key().to_bytes().to_vec();
        witness.extend_from_slice(&session_key.sign(&tx.signing_bytes(&crate::TEST_GENESIS)).to_bytes());
        tx.signature = Some(policy_signature(1, &hex::encode(witness)).unwrap());
        run(&mut view, &tx, 2).unwrap();
        assert_eq!(
            view.get(&AccountKey(&sender))
                .unwrap()
                .unwrap()
                .programmable
                .unwrap()
                .policy
                .sessions[0]
                .allowance,
            0
        );
        let session_signed = |payload| {
            let mut action = Action {
                sender: sender.clone(),
                nonce: 2,
                signature: None,
                payload,
            };
            let mut witness = session_key.verifying_key().to_bytes().to_vec();
            witness.extend_from_slice(&session_key.sign(&action.signing_bytes(&crate::TEST_GENESIS)).to_bytes());
            action.signature = Some(policy_signature(1, &hex::encode(witness)).unwrap());
            action
        };
        assert!(
            run(&mut view, &session_signed(tx.payload.clone()), 3).is_err(),
            "allowance cannot be reused"
        );
        assert!(
            run(&mut view, &session_signed(tx.payload.clone()), 20).is_err(),
            "expiry is exclusive"
        );
        assert!(
            run(
                &mut view,
                &session_signed(ActionPayload::Transfer {
                    to: sender.clone(),
                    amount: 0
                }),
                3
            )
            .is_err(),
            "recipient outside scope"
        );
        assert!(
            run(
                &mut view,
                &session_signed(ActionPayload::AccountPolicy(
                    AccountPolicyAction::SetPolicy {
                        policy: policy(&keys)
                    }
                )),
                3
            )
            .is_err(),
            "session cannot escalate to owner"
        );
        assert!(
            run(
                &mut view,
                &signed(&sender, 2, tx.payload.clone(), &guardians, Some(2)),
                3
            )
            .is_err(),
            "guardian cannot spend"
        );
        let start = |nonce| {
            signed(
                &sender,
                nonce,
                ActionPayload::AccountPolicy(AccountPolicyAction::StartRecovery {
                    owners: owners(&new, 2),
                }),
                &guardians,
                Some(2),
            )
        };
        run(&mut view, &start(2), 3).unwrap();
        let finish = |nonce| {
            signed(
                &sender,
                nonce,
                ActionPayload::AccountPolicy(AccountPolicyAction::ExecuteRecovery),
                &guardians,
                Some(2),
            )
        };
        assert!(
            run(&mut view, &finish(3), 7)
                .unwrap_err()
                .to_string()
                .contains("timelock")
        );
        run(
            &mut view,
            &signed(
                &sender,
                3,
                ActionPayload::AccountPolicy(AccountPolicyAction::CancelRecovery),
                &keys,
                Some(0),
            ),
            7,
        )
        .unwrap();
        assert!(run(&mut view, &finish(4), 8).is_err());
        run(&mut view, &start(4), 9).unwrap();
        run(&mut view, &finish(5), 14).unwrap();
        assert!(
            run(
                &mut view,
                &signed(&sender, 6, tx.payload.clone(), &keys, Some(0)),
                14
            )
            .is_err()
        );
        run(
            &mut view,
            &signed(&sender, 6, tx.payload, &new, Some(0)),
            14,
        )
        .unwrap();
        assert!(
            view.get(&AccountKey(&sender))
                .unwrap()
                .unwrap()
                .programmable
                .unwrap()
                .policy
                .sessions
                .is_empty()
        );
        // The owner can cancel even with a zero spending budget.
        let mut locked = policy(&new);
        locked.limits.push(SpendingLimit {
            asset: SpendAsset::Native,
            period_blocks: 100,
            amount: 0,
        });
        locked.recovery = Some(RecoveryPolicy {
            guardians: owners(&guardians, 2),
            delay_blocks: 5,
        });
        run(
            &mut view,
            &signed(
                &sender,
                7,
                ActionPayload::AccountPolicy(AccountPolicyAction::SetPolicy { policy: locked }),
                &new,
                Some(0),
            ),
            15,
        )
        .unwrap();
        run(&mut view, &start(8), 15).unwrap();
        run(
            &mut view,
            &signed(
                &sender,
                9,
                ActionPayload::AccountPolicy(AccountPolicyAction::CancelRecovery),
                &new,
                Some(0),
            ),
            16,
        )
        .unwrap();
        run(
            &mut view,
            &signed(
                &sender,
                10,
                ActionPayload::AccountPolicy(AccountPolicyAction::RotateMembers {
                    owners: owners(&keys, 2),
                }),
                &new,
                Some(0),
            ),
            16,
        )
        .unwrap();
    }

    #[test]
    fn writes_programmable_account_client_vectors() {
        use serde_json::json;
        let keys = [key(7), key(8), key(9)];
        let sender = multisig_address(2, &owners(&keys, 2).members).unwrap();
        let recipient = Address::from_pubkey_bytes(&key(6).verifying_key().to_bytes()).unwrap();
        let mut p = policy(&keys);
        p.limits = vec![SpendingLimit {
            asset: SpendAsset::Native,
            period_blocks: 256,
            amount: (1u128 << 64) + 7,
        }];
        p.recipients = Some(vec![recipient.clone()]);
        let session = SessionKey {
            public_key: key(6).verifying_key().to_bytes(),
            expires_at: 65536,
            asset: SpendAsset::Native,
            allowance: 500,
            recipients: vec![recipient.clone()],
        };
        p.sessions = vec![session.clone()];
        p.recovery = Some(RecoveryPolicy {
            guardians: owners(&keys, 2),
            delay_blocks: 251,
        });
        let threshold = json!({"threshold": 2, "members": p.owners.members.iter().map(hex::encode).collect::<Vec<_>>()});
        let session_json = json!({"publicKey": hex::encode(session.public_key), "expiresAt": "65536", "asset": "native", "allowance": "500", "recipients": [recipient]});
        let policy_json = json!({"owners": threshold, "limits": [{"asset": "native", "periodBlocks": "256", "amount": ((1u128 << 64) + 7).to_string()}],
            "recipients": [recipient], "sessions": [session_json], "recovery": {"guardians": threshold, "delayBlocks": "251"}});
        let variants = [
            (
                "setAccountPolicy",
                json!({"policy": policy_json}),
                AccountPolicyAction::SetPolicy { policy: p.clone() },
            ),
            (
                "rotateAccountMembers",
                json!({"owners": threshold}),
                AccountPolicyAction::RotateMembers {
                    owners: p.owners.clone(),
                },
            ),
            (
                "addSessionKey",
                json!({"session": session_json}),
                AccountPolicyAction::AddSession {
                    session: session.clone(),
                },
            ),
            (
                "revokeSessionKey",
                json!({"publicKey": hex::encode(session.public_key)}),
                AccountPolicyAction::RevokeSession {
                    public_key: session.public_key,
                },
            ),
            (
                "startAccountRecovery",
                json!({"owners": threshold}),
                AccountPolicyAction::StartRecovery {
                    owners: p.owners.clone(),
                },
            ),
            (
                "cancelAccountRecovery",
                json!({}),
                AccountPolicyAction::CancelRecovery,
            ),
            (
                "executeAccountRecovery",
                json!({}),
                AccountPolicyAction::ExecuteRecovery,
            ),
        ];
        let fixtures = variants.into_iter().map(|(name, input, payload)| {
            let mode = if matches!(payload, AccountPolicyAction::StartRecovery { .. } | AccountPolicyAction::ExecuteRecovery) { 2 } else { 0 };
            let action = signed(&sender, 251, ActionPayload::AccountPolicy(payload), &keys, Some(mode));
            action.verify_account_signature(Some(&ProgrammableAccount { policy: p.clone(), counters: vec![], pending_recovery: None }), &crate::TEST_GENESIS).unwrap();
            json!({"name": name, "input": input, "payload": hex::encode(bincode::serde::encode_to_vec(&action.payload, wire_config()).unwrap()),
                "signing_bytes": hex::encode(action.signing_bytes(&crate::TEST_GENESIS)), "signature": action.signature, "mode": if mode == 2 { "guardian" } else { "owner" }})
        }).collect::<Vec<_>>();
        let document = json!({"genesis_hash": hex::encode(crate::TEST_GENESIS), "sender": sender, "nonce": 251, "policy": policy_json, "members": threshold,
            "seeds": keys.iter().map(|k| hex::encode(k.to_bytes())).collect::<Vec<_>>(), "fixtures": fixtures});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/ts/fixtures/account-policies.json");
        std::fs::write(
            path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
    }
}
