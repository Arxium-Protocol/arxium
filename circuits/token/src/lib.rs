// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Permissionless crypto tokens (`AssetClass::Token`).
//!
//! Tokens share the regulated-asset ledger — the `Asset` record, the
//! `AssetBalanceKey` balances and the holder index — so every reader that
//! already understands asset balances (RPC, Retracer, Explorer, wallets)
//! understands tokens. What they do not share is logic: no claims, no
//! jurisdictions, no freeze, no forced transfer, no lock-ups. A creator's
//! only powers are minting, while the token is mintable, and renouncing that.
//!
//! Every function refuses a non-`Token` asset, and `circuit-rwa-asset`'s
//! runtime glue refuses `Token` ones, so neither path can be used to reach
//! around the other's rules.
//!
//! Nonces are left to the runtime's generic `consume_nonce`; like the
//! regulated corporate actions, nothing here reads or bumps one.

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{AccountKey, AssetBalanceKey, KvRead};
use xc_primitives::{AccountEntry, Address, Asset, AssetClass, AssetRef, treasury_account};
use xc_storage::{AccountUpdates, AssetBalanceUpdates, StorageError};

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("{asset} is not a token")]
    NotAToken { asset: AssetRef },
    #[error("only the creator ({creator}) of {asset} may do this, got {sender}")]
    NotCreator {
        asset: AssetRef,
        creator: Address,
        sender: Address,
    },
    #[error("minting of {asset} has been renounced")]
    MintRenounced { asset: AssetRef },
    #[error("amount must be positive")]
    ZeroAmount,
    #[error("a token that can never be minted needs a positive initial supply")]
    EmptyFixedSupply,
    #[error("minting {amount} of {asset} would raise supply to {resulting}, over the cap of {cap}")]
    SupplyCapExceeded {
        asset: AssetRef,
        cap: u128,
        resulting: u128,
        amount: u128,
    },
    #[error("supply of {asset} would overflow u128")]
    SupplyOverflow { asset: AssetRef },
    #[error("insufficient {asset} balance for {holder}: has {balance}, needs {amount}")]
    InsufficientBalance {
        asset: AssetRef,
        holder: Address,
        balance: u128,
        amount: u128,
    },
    #[error("{creator} cannot pay the {fee} IUM token creation fee: balance is {balance}")]
    CannotPayCreateFee {
        creator: Address,
        balance: u128,
        fee: u128,
    },
}

fn require_token(asset: &Asset) -> Result<(), TokenError> {
    if asset.asset_class != AssetClass::Token {
        return Err(TokenError::NotAToken {
            asset: asset.asset_ref.clone(),
        });
    }
    Ok(())
}

fn require_creator(asset: &Asset, sender: &Address) -> Result<(), TokenError> {
    if sender != &asset.issuer {
        return Err(TokenError::NotCreator {
            asset: asset.asset_ref.clone(),
            creator: asset.issuer.clone(),
            sender: sender.clone(),
        });
    }
    Ok(())
}

fn balance_of<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &AssetRef,
    owner: &Address,
) -> Result<u128, StorageError> {
    Ok(view.get(&AssetBalanceKey { asset, owner })?.unwrap_or(0))
}

/// Unlike the regulated circuit, the creator counts: a token creator holding
/// supply is an ordinary holder, not an issuer warehousing unissued units.
fn track_holder(asset: &mut Asset, before: u128, after: u128) {
    match (before == 0, after == 0) {
        (true, false) => asset.holder_count = asset.holder_count.saturating_add(1),
        (false, true) => asset.holder_count = asset.holder_count.saturating_sub(1),
        _ => {}
    }
}

/// Supply check and credit shared by creation and `apply_mint`. Checked
/// before any write so a rejected mint leaves nothing half-applied.
fn mint_into<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    to: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, TokenError> {
    let overflow = || TokenError::SupplyOverflow {
        asset: asset.asset_ref.clone(),
    };
    let resulting = asset
        .total_supply
        .checked_add(amount)
        .ok_or_else(overflow)?;
    if let Some(cap) = asset.max_supply
        && resulting > cap
    {
        return Err(TokenError::SupplyCapExceeded {
            asset: asset.asset_ref.clone(),
            cap,
            resulting,
            amount,
        });
    }
    let before = balance_of(view, &asset.asset_ref, to)?;
    let after = before.checked_add(amount).ok_or_else(overflow)?;
    asset.total_supply = resulting;
    track_holder(asset, before, after);
    Ok(AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), to.clone()),
        after,
    )])))
}

/// `TokenAction::Create`, given the freshly built record (the runtime owns
/// validation of symbol/name/decimals and the uniqueness of the ref).
/// Charges `create_fee` from the creator to `treasury_account()` and mints
/// `initial_supply` to the creator. A non-mintable token must arrive with
/// `issuance_locked` already set.
pub fn apply_create<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    initial_supply: u128,
    create_fee: u128,
) -> Result<(AccountUpdates, AssetBalanceUpdates), TokenError> {
    require_token(asset)?;
    if initial_supply == 0 && asset.issuance_locked {
        return Err(TokenError::EmptyFixedSupply);
    }
    let creator = asset.issuer.clone();
    let assets = if initial_supply > 0 {
        mint_into(view, asset, &creator, initial_supply)?
    } else {
        AssetBalanceUpdates::default()
    };

    let mut accounts = BTreeMap::new();
    if create_fee > 0 {
        let mut payer = view.get(&AccountKey(&creator))?.unwrap_or(AccountEntry {
            balance: 0,
            ..Default::default()
        });
        payer.balance = payer.balance.checked_sub(create_fee).ok_or_else(|| {
            TokenError::CannotPayCreateFee {
                creator: creator.clone(),
                balance: payer.balance,
                fee: create_fee,
            }
        })?;
        let treasury = treasury_account();
        let mut sink = view.get(&AccountKey(&treasury))?.unwrap_or_default();
        // ponytail: saturating — the treasury overflowing u128 IUM would
        // need more than every ARX that exists.
        sink.balance = sink.balance.saturating_add(create_fee);
        accounts.insert(creator, payer);
        accounts.insert(treasury, sink);
    }
    Ok((AccountUpdates(accounts), assets))
}

/// Creator mints `amount` to `to`, while minting has not been renounced.
pub fn apply_mint<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    sender: &Address,
    to: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, TokenError> {
    require_token(asset)?;
    require_creator(asset, sender)?;
    if asset.issuance_locked {
        return Err(TokenError::MintRenounced {
            asset: asset.asset_ref.clone(),
        });
    }
    if amount == 0 {
        return Err(TokenError::ZeroAmount);
    }
    mint_into(view, asset, to, amount)
}

/// Plain transfer. No gates beyond the balance: that is the whole point of
/// a token as opposed to a regulated asset.
pub fn apply_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, TokenError> {
    require_token(asset)?;
    if amount == 0 {
        return Err(TokenError::ZeroAmount);
    }
    let from_balance = balance_of(view, &asset.asset_ref, from)?;
    if from_balance < amount {
        return Err(TokenError::InsufficientBalance {
            asset: asset.asset_ref.clone(),
            holder: from.clone(),
            balance: from_balance,
            amount,
        });
    }
    // Self-transfer is balance-neutral — computing it would read the
    // not-yet-applied debit as the credit (`circuit_account` does the same).
    if from == to {
        return Ok(AssetBalanceUpdates::default());
    }
    let to_balance = balance_of(view, &asset.asset_ref, to)?;
    let to_after = to_balance
        .checked_add(amount)
        .ok_or_else(|| TokenError::SupplyOverflow {
            asset: asset.asset_ref.clone(),
        })?;
    track_holder(asset, from_balance, from_balance - amount);
    track_holder(asset, to_balance, to_after);
    Ok(AssetBalanceUpdates(BTreeMap::from([
        (
            (asset.asset_ref.clone(), from.clone()),
            from_balance - amount,
        ),
        ((asset.asset_ref.clone(), to.clone()), to_after),
    ])))
}

/// Any holder burns their own units; supply follows.
pub fn apply_burn<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    holder: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, TokenError> {
    require_token(asset)?;
    if amount == 0 {
        return Err(TokenError::ZeroAmount);
    }
    let balance = balance_of(view, &asset.asset_ref, holder)?;
    if balance < amount {
        return Err(TokenError::InsufficientBalance {
            asset: asset.asset_ref.clone(),
            holder: holder.clone(),
            balance,
            amount,
        });
    }
    // Balance ≤ supply is an invariant every mint and transfer keeps, so
    // this only saturates on already-corrupt state.
    asset.total_supply = asset.total_supply.saturating_sub(amount);
    track_holder(asset, balance, balance - amount);
    Ok(AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), holder.clone()),
        balance - amount,
    )])))
}

/// Creator permanently gives up minting; supply is fixed from here on.
/// Idempotent — renouncing twice is a successful no-op.
pub fn apply_renounce_mint(asset: &mut Asset, sender: &Address) -> Result<(), TokenError> {
    require_token(asset)?;
    require_creator(asset, sender)?;
    asset.issuance_locked = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::AssetMetadata;
    use xc_storage::{ArxiumDb, BatchWritable};

    fn temp_db() -> ArxiumDb {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
        ArxiumDb::open(&std::env::temp_dir().join(format!("arxium-test-token-{id}"))).unwrap()
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    fn token(creator: &Address, mintable: bool, max_supply: Option<u128>) -> Asset {
        let mut asset = Asset::register(
            AssetRef::derive(creator, "arxd").unwrap(),
            "arxd",
            creator.clone(),
            false,
            AssetMetadata {
                asset_class: AssetClass::Token,
                decimals: 6,
                max_supply,
                symbol: "ARXD".into(),
                name: "Arx Dollar".into(),
                ..Default::default()
            },
            1,
        );
        asset.issuance_locked = !mintable;
        asset
    }

    fn fund(db: &ArxiumDb, who: &Address, balance: u128) {
        let entry = AccountEntry {
            balance,
            ..Default::default()
        };
        commit(db, &AccountUpdates(BTreeMap::from([(who.clone(), entry)])));
    }

    fn commit(db: &ArxiumDb, updates: &impl BatchWritable) {
        db.write_batch(updates).unwrap();
    }

    #[test]
    fn create_charges_fee_to_treasury_and_mints_to_creator() {
        let db = temp_db();
        let alice = addr(1);
        fund(&db, &alice, 1_000);
        let mut t = token(&alice, true, None);
        let (accounts, assets) = apply_create(&db, &mut t, 500, 300).unwrap();
        assert_eq!(accounts.0[&alice].balance, 700);
        assert_eq!(accounts.0[&treasury_account()].balance, 300);
        assert_eq!(assets.0[&(t.asset_ref.clone(), alice.clone())], 500);
        assert_eq!((t.total_supply, t.holder_count), (500, 1));
    }

    #[test]
    fn create_refuses_unaffordable_fee_empty_fixed_supply_and_non_tokens() {
        let db = temp_db();
        let alice = addr(1);
        fund(&db, &alice, 10);
        assert!(matches!(
            apply_create(&db, &mut token(&alice, true, None), 1, 11),
            Err(TokenError::CannotPayCreateFee { .. })
        ));
        assert!(matches!(
            apply_create(&db, &mut token(&alice, false, None), 0, 0),
            Err(TokenError::EmptyFixedSupply)
        ));
        assert!(matches!(
            apply_create(&db, &mut Asset::new("gold", alice.clone(), false), 1, 0),
            Err(TokenError::NotAToken { .. })
        ));
        assert!(matches!(
            apply_create(&db, &mut token(&alice, true, Some(5)), 6, 0),
            Err(TokenError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn mint_is_creator_only_capped_and_stops_after_renounce() {
        let db = temp_db();
        let (alice, bob) = (addr(1), addr(2));
        let mut t = token(&alice, true, Some(100));
        assert!(matches!(
            apply_mint(&db, &mut t, &bob, &bob, 1),
            Err(TokenError::NotCreator { .. })
        ));
        let minted = apply_mint(&db, &mut t, &alice, &bob, 100).unwrap();
        assert_eq!(minted.0[&(t.asset_ref.clone(), bob.clone())], 100);
        commit(&db, &minted);
        assert!(matches!(
            apply_mint(&db, &mut t, &alice, &bob, 1),
            Err(TokenError::SupplyCapExceeded { .. })
        ));

        let mut open = token(&alice, true, None);
        assert!(matches!(
            apply_renounce_mint(&mut open, &bob),
            Err(TokenError::NotCreator { .. })
        ));
        apply_renounce_mint(&mut open, &alice).unwrap();
        apply_renounce_mint(&mut open, &alice).unwrap();
        assert!(matches!(
            apply_mint(&db, &mut open, &alice, &alice, 1),
            Err(TokenError::MintRenounced { .. })
        ));
    }

    #[test]
    fn transfer_moves_balance_tracks_holders_and_has_no_other_gates() {
        let db = temp_db();
        let (alice, bob) = (addr(1), addr(2));
        let mut t = token(&alice, true, None);
        commit(&db, &apply_mint(&db, &mut t, &alice, &alice, 10).unwrap());

        assert!(matches!(
            apply_transfer(&db, &mut t, &alice, &bob, 11),
            Err(TokenError::InsufficientBalance { .. })
        ));
        assert!(
            apply_transfer(&db, &mut t, &alice, &alice, 5)
                .unwrap()
                .0
                .is_empty()
        );

        let moved = apply_transfer(&db, &mut t, &alice, &bob, 10).unwrap();
        assert_eq!(moved.0[&(t.asset_ref.clone(), alice.clone())], 0);
        assert_eq!(moved.0[&(t.asset_ref.clone(), bob.clone())], 10);
        // Alice emptied out, Bob arrived: still one holder.
        assert_eq!(t.holder_count, 1);
        assert!(matches!(
            apply_transfer(&db, &mut t, &alice, &bob, 0),
            Err(TokenError::ZeroAmount)
        ));
    }

    #[test]
    fn any_holder_burns_own_units_and_supply_follows() {
        let db = temp_db();
        let (alice, bob) = (addr(1), addr(2));
        let mut t = token(&alice, true, None);
        commit(&db, &apply_mint(&db, &mut t, &alice, &bob, 10).unwrap());
        assert!(matches!(
            apply_burn(&db, &mut t, &bob, 11),
            Err(TokenError::InsufficientBalance { .. })
        ));
        let burned = apply_burn(&db, &mut t, &bob, 10).unwrap();
        assert_eq!(burned.0[&(t.asset_ref.clone(), bob.clone())], 0);
        assert_eq!((t.total_supply, t.holder_count), (0, 0));
    }
}
