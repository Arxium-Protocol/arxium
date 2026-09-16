// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_circuit::{AssetKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Address, Asset, AssetMetadata, AssetRef};
use xc_storage::StorageError;

use crate::ChainAction;

/// `asset_id` is the issuer-scoped slug the `AssetRef` is derived from and
/// what every downstream consumer displays next to the ref, so it is bounded
/// here, at the only place a slug enters state.
const MAX_ASSET_ID_LEN: usize = 64;

/// Display ticker. Not unique anywhere and never resolved by the node — the
/// bounds exist so a client can render it in a fixed-width column.
const MAX_SYMBOL_LEN: usize = 12;

/// Display name, free-form UTF-8.
const MAX_NAME_LEN: usize = 64;

/// `metadata_uri` lands in a merkleized, permanent record. The 1 MiB
/// `MAX_WIRE_MESSAGE_SIZE` ceiling stops a peer exhausting memory during
/// decode, but on its own it would happily let a single registration park
/// most of a megabyte in the state trie forever.
const MAX_METADATA_URI_LEN: usize = 2048;

/// Display scale only, and 18 is what every downstream formatter assumes.
/// `u8` alone would permit 255, which no consumer can render.
const MAX_DECIMALS: u8 = 18;

/// A `ForcedTransfer`'s `reason` rides in the block forever, so it is capped —
/// generously, since this is a legal justification a human writes, but capped,
/// because `MAX_WIRE_MESSAGE_SIZE` alone would permit most of a megabyte of it.
const MAX_REASON_LEN: usize = 512;

/// Charset is restricted rather than case-folded, for two reasons.
///
/// Case: folding would mean the id stored, indexed and shown by every
/// consumer is not the id the issuer submitted, so `Gold` would silently
/// surface as `gold` in the explorer. Rejecting rules out the `Gold`/`gold`
/// collision while keeping stored id == submitted id.
///
/// Punctuation: the slug no longer appears in any storage key (those are
/// keyed on the derived `AssetRef`), but it is shown everywhere and lands in
/// the ref preimage, so the allowlist stays: a slug is a slug.
fn validate_asset_id(asset_id: &str) -> anyhow::Result<()> {
    if asset_id.is_empty() {
        anyhow::bail!("asset_id must not be empty");
    }
    if asset_id.len() > MAX_ASSET_ID_LEN {
        anyhow::bail!(
            "asset_id is {} bytes, over the {MAX_ASSET_ID_LEN}-byte limit",
            asset_id.len()
        );
    }
    if let Some(bad) = asset_id
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_'))
    {
        anyhow::bail!(
            "asset_id {asset_id:?} contains {bad:?}: only lowercase ascii, digits, '-' and '_' are allowed"
        );
    }
    Ok(())
}

/// Uppercase is required rather than applied: a lowercase symbol is rejected,
/// never silently upcased, so what is stored is what the issuer signed.
fn validate_symbol(symbol: &str) -> anyhow::Result<()> {
    if symbol.is_empty() || symbol.len() > MAX_SYMBOL_LEN {
        anyhow::bail!("symbol must be 1–{MAX_SYMBOL_LEN} bytes, got {}", symbol.len());
    }
    if let Some(bad) = symbol.chars().find(|c| !(c.is_ascii_uppercase() || c.is_ascii_digit())) {
        anyhow::bail!("symbol {symbol:?} contains {bad:?}: only A-Z and 0-9 are allowed");
    }
    Ok(())
}

fn validate_metadata(metadata: &AssetMetadata) -> anyhow::Result<()> {
    validate_symbol(&metadata.symbol)?;
    if metadata.name.is_empty() || metadata.name.len() > MAX_NAME_LEN {
        anyhow::bail!("name must be 1–{MAX_NAME_LEN} bytes, got {}", metadata.name.len());
    }
    if metadata.decimals > MAX_DECIMALS {
        anyhow::bail!(
            "decimals is {}, over the maximum of {MAX_DECIMALS}",
            metadata.decimals
        );
    }
    if let Some(uri) = &metadata.metadata_uri
        && uri.len() > MAX_METADATA_URI_LEN
    {
        anyhow::bail!(
            "metadata_uri is {} bytes, over the {MAX_METADATA_URI_LEN}-byte limit",
            uri.len()
        );
    }
    // `Some(vec![])` is left valid on purpose: it means no jurisdiction may
    // hold the asset, which is useless but unambiguous, and is distinct from
    // `None` (unrestricted). Rejecting it would make `None` and empty behave
    // the same, which is exactly the confusion the two-state field avoids.
    for code in metadata.allowed_jurisdictions.iter().flatten() {
        if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
            anyhow::bail!(
                "jurisdiction {code:?} is not a 2-letter uppercase ISO-3166-1 alpha-2 code"
            );
        }
    }
    Ok(())
}

pub(crate) fn register_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset_id: &str,
    compliance_required: bool,
    metadata: &AssetMetadata,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    validate_asset_id(asset_id)?;
    validate_metadata(metadata)?;
    // The ref commits to `(sender, asset_id)`, so an existing record at it is
    // exactly "this issuer already has this slug" — the per-issuer uniqueness
    // check needs no alias index.
    let asset_ref = AssetRef::derive(&action.sender, asset_id)?;
    if view.get(&AssetKey(&asset_ref))?.is_some() {
        anyhow::bail!("{} already has an asset with id {asset_id} ({asset_ref})", action.sender);
    }
    let asset = Asset::register(
        asset_ref,
        asset_id,
        action.sender.clone(),
        compliance_required,
        metadata.clone(),
        current_height,
    );
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

/// Every handler but registration goes through here: an unknown ref is a
/// clean rejection, never an implicit create.
fn resolve_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &AssetRef,
) -> anyhow::Result<Asset> {
    view.get(&AssetKey(asset))?
        .ok_or_else(|| anyhow::anyhow!("unknown asset {asset}"))
}

pub(crate) fn issue_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = resolve_asset(view, asset)?;
    let (accounts, assets) =
        circuit_rwa_asset::apply_issue(view, &mut asset, &action.sender, action.nonce, amount)?;
    // `apply_issue` advanced `total_supply`, so the record has to go back.
    // `asset_registration` is the channel for that despite the name: it is a
    // plain `put` on `AssetKey` (`BlockView::apply_asset_registration`), an
    // upsert rather than an insert, and `asset_index_updates` dedupes the
    // registry list by id, so re-emitting an already-registered asset is
    // harmless.
    Ok(BlockUpdates {
        accounts,
        assets,
        asset_registration: Some(asset),
        ..Default::default()
    })
}

pub(crate) fn transfer_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    to: &Address,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let asset = resolve_asset(view, asset)?;
    let (accounts, assets) = circuit_rwa_asset::apply_compliant_transfer(
        view,
        &asset,
        &action.sender,
        action.nonce,
        to,
        amount,
    )?;
    Ok(BlockUpdates {
        accounts,
        assets,
        ..Default::default()
    })
}

/// Sets or clears `Asset.frozen` (`FreezeAsset`/`UnfreezeAsset`). Authorized
/// for the asset's own issuer or the chain governor: the issuer is the party
/// that answers for the instrument, and the governor is the regulatory
/// backstop for when the issuer is the problem.
///
/// Idempotent in both directions — freezing an already-frozen asset is a
/// successful no-op write, so a caller never needs to read the current flag
/// first. It costs the action fee like anything else; it does not consume the
/// sender's nonce, same as the other non-balance handlers (`register_asset`,
/// the `identity::*` ones) — only the circuits that move value do that.
pub(crate) fn set_frozen<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    frozen: bool,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = resolve_asset(view, asset)?;
    if action.sender != asset.issuer {
        crate::identity::require_governor(view, action).map_err(|_| {
            anyhow::anyhow!(
                "{} is neither the issuer of {} nor the chain governor",
                action.sender, asset.asset_ref
            )
        })?;
    }
    asset.frozen = frozen;
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

/// Moves an asset balance on the governor's authority alone
/// (`ForcedTransfer`) — no signature from `from`, and none of the compliance,
/// claim, jurisdiction or freeze gates, which is the entire point: the cases
/// this exists for (court order, sanctions, a lost key) are ones ordinary
/// compliance refuses. It cannot mint — `circuit_rwa_asset::apply_forced_transfer`
/// still requires `from` to hold the balance.
///
/// `reason` is required and length-capped. It isn't written to state; the
/// block carrying the action is the audit record.
pub(crate) fn forced_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    from: &Address,
    to: &Address,
    amount: u128,
    reason: &str,
) -> anyhow::Result<BlockUpdates> {
    if reason.trim().is_empty() {
        anyhow::bail!("a forced transfer needs a non-empty reason");
    }
    if reason.len() > MAX_REASON_LEN {
        anyhow::bail!(
            "reason is {} bytes, over the {MAX_REASON_LEN}-byte limit",
            reason.len()
        );
    }
    crate::identity::require_governor(view, action)
        .map_err(|_| anyhow::anyhow!("only the chain governor may force a transfer"))?;

    let asset = resolve_asset(view, asset)?;
    let assets = circuit_rwa_asset::apply_forced_transfer(view, &asset, from, to, amount)?;
    Ok(BlockUpdates {
        assets,
        ..Default::default()
    })
}

fn require_issuer<V: KvRead<Error = StorageError>>(view: &V, action: &ChainAction, asset: &AssetRef) -> anyhow::Result<Asset> {
    let asset = resolve_asset(view, asset)?;
    if action.sender != asset.issuer {
        anyhow::bail!("only the issuer ({}) of {} may do this, got {}", asset.issuer, asset.asset_ref, action.sender);
    }
    Ok(asset)
}

pub(crate) fn burn_asset<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = require_issuer(view, action, asset)?;
    if amount == 0 {
        anyhow::bail!("burn amount must be positive");
    }
    let assets = circuit_rwa_asset::apply_burn(view, &mut asset, &action.sender, amount)?;
    Ok(BlockUpdates {
        assets,
        asset_registration: Some(asset),
        ..Default::default()
    })
}

pub(crate) fn set_holder_frozen<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    holder: &Address,
    frozen: bool,
) -> anyhow::Result<BlockUpdates> {
    let asset = require_issuer(view, action, asset)?;
    let holder_states = circuit_rwa_asset::apply_set_holder_frozen(view, &asset, holder, frozen)?;
    Ok(BlockUpdates {
        holder_states,
        ..Default::default()
    })
}

pub(crate) fn lock_holder_amount<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    holder: &Address,
    amount: u128,
    lock: bool,
) -> anyhow::Result<BlockUpdates> {
    let asset = require_issuer(view, action, asset)?;
    if amount == 0 {
        anyhow::bail!("lock amount must be positive");
    }
    let holder_states = circuit_rwa_asset::apply_lock_amount(view, &asset, holder, amount, lock)?;
    Ok(BlockUpdates {
        holder_states,
        ..Default::default()
    })
}

/// The issuer's forced transfer: same semantics and audit `reason` as the
/// governor's, restricted to the issuer's own assets.
pub(crate) fn issuer_forced_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    from: &Address,
    to: &Address,
    amount: u128,
    reason: &str,
) -> anyhow::Result<BlockUpdates> {
    if reason.trim().is_empty() {
        anyhow::bail!("a forced transfer needs a non-empty reason");
    }
    if reason.len() > MAX_REASON_LEN {
        anyhow::bail!("reason is {} bytes, over the {MAX_REASON_LEN}-byte limit", reason.len());
    }
    let asset = require_issuer(view, action, asset)?;
    let assets = circuit_rwa_asset::apply_forced_transfer(view, &asset, from, to, amount)?;
    Ok(BlockUpdates {
        assets,
        ..Default::default()
    })
}

pub(crate) fn issue_asset_to<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    to: &Address,
    amount: u128,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = require_issuer(view, action, asset)?;
    if amount == 0 {
        anyhow::bail!("issue amount must be positive");
    }
    let assets = circuit_rwa_asset::apply_issue_to(view, &mut asset, to, amount)?;
    Ok(BlockUpdates {
        assets,
        asset_registration: Some(asset),
        ..Default::default()
    })
}

/// `LockIssuance`: issuer-only, one-way. Also pins `max_supply` to what is
/// actually outstanding so the cap a reader sees is the real ceiling.
pub(crate) fn lock_issuance<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = require_issuer(view, action, asset)?;
    asset.issuance_locked = true;
    asset.max_supply = Some(asset.total_supply);
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

/// `TransferIssuer`: the current issuer names its successor. `asset_ref`
/// stays what it was (derived from the original issuer at registration), so
/// every balance key and every link survives the handover.
pub(crate) fn transfer_issuer<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    new_issuer: &Address,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = require_issuer(view, action, asset)?;
    new_issuer.pubkey_bytes().map_err(|e| anyhow::anyhow!("new issuer {new_issuer} is not a valid address: {e}"))?;
    asset.issuer = new_issuer.clone();
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

/// `SetAssetMetadataUri`: issuer-only; `None` clears it.
pub(crate) fn set_metadata_uri<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    metadata_uri: Option<String>,
) -> anyhow::Result<BlockUpdates> {
    let mut asset = require_issuer(view, action, asset)?;
    asset.metadata_uri = metadata_uri;
    Ok(BlockUpdates {
        asset_registration: Some(asset),
        ..Default::default()
    })
}

pub(crate) fn recover_holder<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    asset: &AssetRef,
    lost: &Address,
    replacement: &Address,
) -> anyhow::Result<BlockUpdates> {
    if lost == replacement {
        anyhow::bail!("recovery needs a different replacement address");
    }
    let asset = require_issuer(view, action, asset)?;
    let (assets, holder_states) = circuit_rwa_asset::apply_recover(view, &asset, lost, replacement)?;
    Ok(BlockUpdates {
        assets,
        holder_states,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::ActionPayload;
    use std::collections::HashMap;
    use xc_primitives::Action;
    use xc_storage::BlockView;

    /// The smallest metadata that passes validation — `symbol`/`name` are
    /// mandatory, so `AssetMetadata::default()` no longer registers.
    fn meta() -> AssetMetadata {
        AssetMetadata { symbol: "GOLD".into(), name: "Gold".into(), ..Default::default() }
    }

    fn gold_of(issuer: &Address) -> AssetRef {
        AssetRef::derive(issuer, "gold").unwrap()
    }

    #[test]
    fn transfer_asset_fails_without_recipient_attestation_and_succeeds_after_grant() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let gold = gold_of(&issuer);
        let recipient = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();

        let mut issuer_account = funded(FEE_BUDGET * 4);
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
            payload: ActionPayload::RegisterAsset {
                asset_id: "gold".into(),
                compliance_required: true,
                metadata: meta(),
            },
        };
        let updates = dispatch(&register, &view).unwrap();
        let asset = updates
            .asset_registration
            .clone()
            .expect("asset registered");
        view.put(&AssetKey(&gold), &asset).unwrap();
        view.apply_accounts(&updates.accounts).unwrap();

        // RegisterAsset doesn't touch the sender's account nonce, so the
        // issuer's nonce is still 0 here.
        let issue = Action {
            sender: issuer.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::IssueAsset {
                asset: gold.clone(),
                amount: 1000,
            },
        };
        let updates = dispatch(&issue, &view).unwrap();
        view.apply_accounts(&updates.accounts).unwrap();
        view.apply_asset_balances(&updates.assets).unwrap();
        // Issuance now rewrites the asset record too, to carry `total_supply`.
        let issued = updates
            .asset_registration
            .clone()
            .expect("issue rewrites the record");
        assert_eq!(issued.total_supply, 1000);
        view.put(&AssetKey(&gold), &issued).unwrap();

        // Recipient has no attestation yet — transfer must fail. The
        // compliance check runs before the nonce check, so the rejected
        // attempt doesn't consume nonce 1.
        let transfer = Action {
            sender: issuer.clone(),
            nonce: 1,
            signature: None,
            payload: ActionPayload::TransferAsset {
                asset: gold.clone(),
                to: recipient.clone(),
                amount: 100,
            },
        };
        let err = dispatch(&transfer, &view).unwrap_err();
        assert!(err.to_string().contains("not KYC'd"));

        // ponytail: this test's chain has no configured attestor, so grant
        // via a direct account write instead of round-tripping through
        // `GrantAttestation` dispatch — attestor authorization is covered
        // separately in `identity.rs`'s own tests.
        let mut recipient_account = funded(0);
        recipient_account.identity_hash = Some("kyc-recipient".into());
        view.put(&xc_circuit::AccountKey(&recipient), &recipient_account)
            .unwrap();

        let transfer = Action {
            sender: issuer.clone(),
            nonce: 1,
            signature: None,
            payload: ActionPayload::TransferAsset {
                asset: gold.clone(),
                to: recipient.clone(),
                amount: 100,
            },
        };
        let updates = dispatch(&transfer, &view).unwrap();
        assert_eq!(
            updates.assets.0[&(gold.clone(), recipient.clone())],
            100
        );
        view.apply_accounts(&updates.accounts).unwrap();
        view.apply_asset_balances(&updates.assets).unwrap();

        // Freezing blocks the same transfer that just succeeded, and
        // unfreezing restores it — the one path that proves the flag is read
        // from state rather than only written to it.
        let freeze = Action {
            sender: issuer.clone(),
            nonce: 2,
            signature: None,
            payload: ActionPayload::FreezeAsset {
                asset: gold.clone(),
            },
        };
        let updates = dispatch(&freeze, &view).unwrap();
        let frozen = updates
            .asset_registration
            .clone()
            .expect("freeze rewrites the record");
        assert!(frozen.frozen);
        assert_eq!(
            frozen.total_supply, 1000,
            "freezing must not disturb the supply counter"
        );
        view.put(&AssetKey(&gold), &frozen).unwrap();

        let transfer = Action {
            sender: issuer.clone(),
            nonce: 2,
            signature: None,
            payload: ActionPayload::TransferAsset {
                asset: gold.clone(),
                to: recipient.clone(),
                amount: 10,
            },
        };
        let err = dispatch(&transfer, &view).unwrap_err();
        assert!(err.to_string().contains("is frozen"), "got: {err}");

        let unfreeze = Action {
            sender: issuer.clone(),
            nonce: 2,
            signature: None,
            payload: ActionPayload::UnfreezeAsset {
                asset: gold.clone(),
            },
        };
        let updates = dispatch(&unfreeze, &view).unwrap();
        let thawed = updates
            .asset_registration
            .clone()
            .expect("unfreeze rewrites the record");
        assert!(!thawed.frozen);
        view.put(&AssetKey(&gold), &thawed).unwrap();
        dispatch(&transfer, &view).expect("transfer works again once unfrozen");
    }

    /// The reason the ref exists: two issuers both get `gold`, with distinct
    /// refs and independent supply; the same issuer cannot claim it twice; and
    /// a ref nobody registered is a clean rejection, never an implicit create.
    #[test]
    fn same_slug_is_per_issuer_and_unknown_refs_are_rejected() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(FEE_BUDGET * 8)), (bob.clone(), funded(FEE_BUDGET * 8))]),
            HashMap::new(),
        );
        let register = |sender: &Address| ChainAction {
            sender: sender.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterAsset { asset_id: "gold".into(), compliance_required: false, metadata: meta() },
        };

        let alice_gold = dispatch_at(&register(&alice), &view, 0).unwrap().asset_registration.unwrap();
        view.put(&AssetKey(&alice_gold.asset_ref), &alice_gold).unwrap();
        let bob_gold = dispatch_at(&register(&bob), &view, 0).unwrap().asset_registration.unwrap();
        view.put(&AssetKey(&bob_gold.asset_ref), &bob_gold).unwrap();
        assert_ne!(alice_gold.asset_ref, bob_gold.asset_ref);
        assert_eq!(alice_gold.asset_ref, gold_of(&alice));
        assert_eq!(bob_gold.asset_id, "gold");

        let err = dispatch_at(&register(&alice), &view, 0).unwrap_err();
        assert!(err.to_string().contains("already has an asset with id gold"), "{err}");

        // Supply is per ref: issuing under alice's leaves bob's untouched.
        let issue = ChainAction {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::IssueAsset { asset: alice_gold.asset_ref.clone(), amount: 10 },
        };
        let updates = dispatch_at(&issue, &view, 0).unwrap();
        assert_eq!(updates.asset_registration.unwrap().total_supply, 10);
        assert!(!updates.assets.0.contains_key(&(bob_gold.asset_ref.clone(), alice.clone())));

        let unknown = ChainAction {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::TransferAsset { asset: AssetRef::derive(&alice, "nope").unwrap(), to: bob.clone(), amount: 1 },
        };
        let err = dispatch_at(&unknown, &view, 0).unwrap_err();
        assert!(err.to_string().contains("unknown asset"), "{err}");
    }

    /// `symbol` is display-only but still validated: empty, over-long,
    /// punctuated and lowercase are all refused — lowercase is not upcased.
    #[test]
    fn register_rejects_bad_symbols_and_names() {
        for bad in ["", "gold", "Gold", "GOLD-X", "G".repeat(MAX_SYMBOL_LEN + 1).as_str()] {
            let err = register("gold", AssetMetadata { symbol: bad.into(), ..meta() }).unwrap_err();
            assert!(err.to_string().contains("symbol"), "symbol {bad:?} should be rejected, got: {err}");
        }
        assert!(register("gold", AssetMetadata { symbol: "G".repeat(MAX_SYMBOL_LEN), ..meta() }).is_ok());
        for bad in ["", "n".repeat(MAX_NAME_LEN + 1).as_str()] {
            let err = register("gold", AssetMetadata { name: bad.into(), ..meta() }).unwrap_err();
            assert!(err.to_string().contains("name"), "name {bad:?} should be rejected, got: {err}");
        }
    }

    fn register(asset_id: &str, metadata: AssetMetadata) -> anyhow::Result<BlockUpdates> {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let view = seeded_view(&db, HashMap::new(), HashMap::new());
        let action = ChainAction {
            sender: issuer,
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterAsset {
                asset_id: asset_id.into(),
                compliance_required: false,
                metadata: metadata.clone(),
            },
        };
        register_asset(&view, &action, asset_id, false, &metadata, 42)
    }

    #[test]
    fn register_stores_issuer_metadata_and_stamps_the_height() {
        let updates = register(
            "gold-a_1",
            AssetMetadata {
                asset_class: xc_primitives::AssetClass::Commodity,
                decimals: 8,
                required_claims: vec![xc_primitives::ClaimTopic::Kyc],
                allowed_jurisdictions: Some(vec!["CH".into(), "DE".into()]),
                max_supply: Some(1_000),
                metadata_uri: Some("https://example.test/prospectus.pdf".into()),
                symbol: "XAU".into(),
                name: "Gold bar".into(),
            },
        )
        .unwrap();
        let asset = updates.asset_registration.expect("registered");
        assert_eq!(asset.decimals, 8);
        assert_eq!(asset.max_supply, Some(1_000));
        assert_eq!(
            asset.allowed_jurisdictions.as_deref(),
            Some(&["CH".to_string(), "DE".to_string()][..])
        );
        assert_eq!(
            asset.registered_at, 42,
            "height comes from the block, not the issuer"
        );
        // Never issuer-settable, whatever the payload says.
        assert_eq!(asset.total_supply, 0);
        assert!(!asset.frozen);
    }

    #[test]
    fn register_rejects_ids_that_are_empty_mixed_case_overlong_or_punctuated() {
        for bad in [
            "", "Gold", "GOLD", "gold:bar", "gold bar", "gold.bar", "goldé",
        ] {
            let err = register(bad, meta()).unwrap_err();
            assert!(
                err.to_string().contains("asset_id"),
                "id {bad:?} should have been rejected on asset_id grounds, got: {err}"
            );
        }
        let overlong = "g".repeat(MAX_ASSET_ID_LEN + 1);
        assert!(
            register(&overlong, meta())
                .unwrap_err()
                .to_string()
                .contains("over the")
        );
        // The boundary itself is fine.
        assert!(register(&"g".repeat(MAX_ASSET_ID_LEN), meta()).is_ok());
    }

    #[test]
    fn register_rejects_unrenderable_decimals_oversized_uris_and_bad_jurisdictions() {
        let err = register(
            "gold",
            AssetMetadata {
                decimals: MAX_DECIMALS + 1,
                ..meta()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("decimals"), "got: {err}");
        assert!(
            register(
                "gold",
                AssetMetadata {
                    decimals: MAX_DECIMALS,
                    ..meta()
                }
            )
            .is_ok()
        );

        let err = register(
            "gold",
            AssetMetadata {
                metadata_uri: Some("u".repeat(MAX_METADATA_URI_LEN + 1)),
                ..meta()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("metadata_uri"), "got: {err}");

        for bad in ["ch", "CHE", "C", "C1"] {
            let err = register(
                "gold",
                AssetMetadata {
                    allowed_jurisdictions: Some(vec![bad.into()]),
                    ..meta()
                },
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("jurisdiction"),
                "code {bad:?}, got: {err}"
            );
        }
        // `None` is unrestricted; `Some(vec![])` is "nobody", and both are legal.
        assert!(
            register(
                "gold",
                AssetMetadata {
                    allowed_jurisdictions: None,
                    ..meta()
                }
            )
            .is_ok()
        );
        assert!(
            register(
                "gold",
                AssetMetadata {
                    allowed_jurisdictions: Some(vec![]),
                    ..meta()
                }
            )
            .is_ok()
        );
    }

    /// Freeze is issuer-or-governor. This chain has no governor configured,
    /// so a third party has no route to it at all.
    #[test]
    fn freeze_rejects_a_sender_who_is_neither_issuer_nor_governor() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let gold = gold_of(&issuer);
        let stranger = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(stranger.clone(), funded(FEE_BUDGET * 2))]),
            HashMap::new(),
        );
        view.put(&AssetKey(&gold), &Asset::new("gold", issuer.clone(), true))
            .unwrap();

        let action = ChainAction {
            sender: stranger.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::FreezeAsset {
                asset: gold.clone(),
            },
        };
        let err = set_frozen(&view, &action, &gold, true).unwrap_err();
        assert!(err.to_string().contains("neither the issuer"), "got: {err}");
    }

    /// A forced transfer is governor-only and must carry a reason. The issuer
    /// is deliberately *not* enough here, unlike freeze: moving someone
    /// else's holding without their signature is a regulatory power, not an
    /// issuer's housekeeping.
    fn dispatch_at(action: &ChainAction, view: &BlockView<'_>, height: u64) -> anyhow::Result<BlockUpdates> {
        crate::dispatch(action, view, &operator_lookup, &operator_validators_lookup, &[], height, &no_bls_owner)
    }

    /// The handover moves every issuer right, and the old key keeps none.
    #[test]
    fn transfer_issuer_hands_over_authority_and_keeps_the_ref() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let successor = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let gold = AssetRef::derive(&issuer, "gold").unwrap();
        let db = temp_db();
        let mut view = seeded_view(&db, HashMap::new(), HashMap::new());
        view.put(&AssetKey(&gold), &Asset::new("gold", issuer.clone(), false)).unwrap();

        let act = |sender: &Address, payload| ChainAction { sender: sender.clone(), nonce: 0, signature: None, payload };
        let err = transfer_issuer(&view, &act(&successor, ActionPayload::TransferIssuer { asset: gold.clone(), new_issuer: successor.clone() }), &gold, &successor).unwrap_err();
        assert!(err.to_string().contains("only the issuer"), "got: {err}");

        let updates = transfer_issuer(&view, &act(&issuer, ActionPayload::TransferIssuer { asset: gold.clone(), new_issuer: successor.clone() }), &gold, &successor).unwrap();
        let handed = updates.asset_registration.unwrap();
        assert_eq!(handed.issuer, successor);
        assert_eq!(handed.asset_ref, gold, "ref is identity — it must not follow the issuer");
        view.put(&AssetKey(&gold), &handed).unwrap();

        let err = set_metadata_uri(&view, &act(&issuer, ActionPayload::SetAssetMetadataUri { asset: gold.clone(), metadata_uri: None }), &gold, Some("x".into())).unwrap_err();
        assert!(err.to_string().contains("only the issuer"), "old issuer must be locked out: {err}");
        let updates = set_metadata_uri(&view, &act(&successor, ActionPayload::SetAssetMetadataUri { asset: gold.clone(), metadata_uri: None }), &gold, Some("ipfs://terms".into())).unwrap();
        assert_eq!(updates.asset_registration.unwrap().metadata_uri.as_deref(), Some("ipfs://terms"));
    }

    #[test]
    fn holder_controls_are_issuer_only_and_flow_through_dispatch() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let gold = gold_of(&issuer);
        let holder = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let stranger = Address::from_pubkey_bytes(&[3u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (issuer.clone(), funded(FEE_BUDGET * 8)),
                (stranger.clone(), funded(FEE_BUDGET * 8)),
            ]),
            HashMap::new(),
        );
        let mut asset = Asset::new("gold", issuer.clone(), false);
        asset.total_supply = 100;
        view.put(&AssetKey(&gold), &asset).unwrap();
        view.put(&xc_circuit::AssetBalanceKey { asset: &gold, owner: &issuer }, &60u128).unwrap();
        view.put(&xc_circuit::AssetBalanceKey { asset: &gold, owner: &holder }, &40u128).unwrap();

        let act = |sender: &Address, payload: ActionPayload| ChainAction { sender: sender.clone(), nonce: 0, signature: None, payload };

        for payload in [
            ActionPayload::BurnAsset { asset: gold.clone(), amount: 1 },
            ActionPayload::SetHolderFrozen { asset: gold.clone(), holder: holder.clone(), frozen: true },
            ActionPayload::LockHolderAmount { asset: gold.clone(), holder: holder.clone(), amount: 1 },
            ActionPayload::IssuerForcedTransfer { asset: gold.clone(), from: holder.clone(), to: issuer.clone(), amount: 1, reason: "x".into() },
            ActionPayload::RecoverHolder { asset: gold.clone(), lost: holder.clone(), replacement: stranger.clone() },
        ] {
            let err = dispatch_at(&act(&stranger, payload), &view, 0).unwrap_err();
            assert!(err.to_string().contains("only the issuer"), "stranger must be refused: {err}");
        }

        let updates = dispatch_at(&act(&issuer, ActionPayload::BurnAsset { asset: gold.clone(), amount: 10 }), &view, 0).unwrap();
        assert_eq!(updates.asset_registration.unwrap().total_supply, 90);
        assert_eq!(updates.assets.0[&(gold.clone(), issuer.clone())], 50);

        let updates = dispatch_at(&act(&issuer, ActionPayload::LockHolderAmount { asset: gold.clone(), holder: holder.clone(), amount: 25 }), &view, 0).unwrap();
        assert_eq!(updates.holder_states.0[&(gold.clone(), holder.clone())].frozen_amount, 25);

        let updates = dispatch_at(&act(&issuer, ActionPayload::IssuerForcedTransfer { asset: gold.clone(), from: holder.clone(), to: issuer.clone(), amount: 40, reason: "court order".into() }), &view, 0).unwrap();
        assert_eq!(updates.assets.0[&(gold.clone(), holder.clone())], 0);
        let err = dispatch_at(&act(&issuer, ActionPayload::IssuerForcedTransfer { asset: gold.clone(), from: holder.clone(), to: issuer.clone(), amount: 1, reason: "  ".into() }), &view, 0).unwrap_err();
        assert!(err.to_string().contains("non-empty reason"), "{err}");
    }

    #[test]
    fn nonce_discipline_activates_at_the_configured_height_for_every_action() {
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let gold = gold_of(&issuer);
        let db = temp_db();
        let view = seeded_view(&db, HashMap::from([(issuer.clone(), funded(FEE_BUDGET * 8))]), HashMap::new());
        let register = |nonce: u64, id: &str| ChainAction {
            sender: issuer.clone(),
            nonce,
            signature: None,
            payload: ActionPayload::RegisterAsset { asset_id: id.into(), compliance_required: false, metadata: meta() },
        };
        let before = crate::NONCE_DISCIPLINE_HEIGHT - 1;
        let after = crate::NONCE_DISCIPLINE_HEIGHT;

        // Legacy: any nonce is accepted and the account's nonce is untouched.
        let updates = dispatch_at(&register(7, "a"), &view, before).unwrap();
        assert_eq!(updates.accounts.0[&issuer].nonce, 0, "pre-activation history must replay unchanged");

        // Strict: the nonce must match and is consumed.
        let err = dispatch_at(&register(7, "b"), &view, after).unwrap_err();
        assert!(err.to_string().contains("invalid nonce"), "{err}");
        let updates = dispatch_at(&register(0, "b"), &view, after).unwrap();
        assert_eq!(updates.accounts.0[&issuer].nonce, 1);
        assert_eq!(updates.accounts.0[&issuer].balance, FEE_BUDGET * 8 - fee_of(&register(0, "b")), "fee still charged once");

        // An action whose circuit already bumps the nonce is not bumped twice.
        let issue = ChainAction { sender: issuer.clone(), nonce: 0, signature: None, payload: ActionPayload::IssueAsset { asset: gold.clone(), amount: 5 } };
        let mut view = view;
        view.put(&AssetKey(&gold), &Asset::new("gold", issuer.clone(), false)).unwrap();
        let updates = dispatch_at(&issue, &view, after).unwrap();
        assert_eq!(updates.accounts.0[&issuer].nonce, 1);
    }

    #[test]
    fn forced_transfer_requires_the_governor_and_a_non_empty_reason() {
        let governor = Address::from_pubkey_bytes(&[7u8; 32]).unwrap();
        let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let gold = gold_of(&issuer);
        let holder = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let receiver = Address::from_pubkey_bytes(&[3u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (governor.clone(), funded(FEE_BUDGET * 4)),
                (issuer.clone(), funded(FEE_BUDGET * 4)),
            ]),
            HashMap::new(),
        );
        view.put(&xc_circuit::GovernorKey, &governor).unwrap();
        view.put(&AssetKey(&gold), &Asset::new("gold", issuer.clone(), true))
            .unwrap();
        view.put(
            &xc_circuit::AssetBalanceKey {
                asset: &gold,
                owner: &holder,
            },
            &100u128,
        )
        .unwrap();

        let action = |sender: &Address, reason: &str| ChainAction {
            sender: sender.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::ForcedTransfer {
                asset: gold.clone(),
                from: holder.clone(),
                to: receiver.clone(),
                amount: 40,
                reason: reason.to_string(),
            },
        };

        let err = forced_transfer(
            &view,
            &action(&issuer, "court order 2026-114"),
            &gold,
            &holder,
            &receiver,
            40,
            "court order 2026-114",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("only the chain governor"),
            "got: {err}"
        );

        // Whitespace is not a reason — the check is on content, not length.
        let err = forced_transfer(
            &view,
            &action(&governor, "  "),
            &gold,
            &holder,
            &receiver,
            40,
            "  ",
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-empty reason"), "got: {err}");

        let err = forced_transfer(
            &view,
            &action(&governor, &"x".repeat(513)),
            &gold,
            &holder,
            &receiver,
            40,
            &"x".repeat(513),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("over the 512-byte limit"),
            "got: {err}"
        );

        let updates = forced_transfer(
            &view,
            &action(&governor, "court order 2026-114"),
            &gold,
            &holder,
            &receiver,
            40,
            "court order 2026-114",
        )
        .unwrap();
        assert_eq!(updates.assets.0[&(gold.clone(), holder.clone())], 60);
        assert_eq!(
            updates.assets.0[&(gold.clone(), receiver.clone())],
            40
        );
    }
}
