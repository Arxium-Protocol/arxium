// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{AccountKey, AssetBalanceKey, AssetHolderStateKey, KvRead};
use xc_primitives::{AccountEntry, Address, Asset, AssetRef, ClaimTopic, CountryCode, HolderState};
use xc_storage::{AccountUpdates, AssetBalanceUpdates, HolderStateUpdates, StorageError};

#[derive(Error, Debug)]
pub enum RwaError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("only the issuer ({issuer}) may issue supply, got sender {sender}")]
    NotIssuer { issuer: Address, sender: Address },
    #[error("invalid nonce for {sender}: expected {expected}, got {got}")]
    InvalidNonce {
        sender: Address,
        expected: u64,
        got: u64,
    },
    #[error("compliance check failed: {address} is not KYC'd/allowlisted")]
    NotCompliant { address: Address },
    #[error("insufficient {asset} balance for {sender}: has {balance}, needs {amount}")]
    InsufficientBalance {
        asset: AssetRef,
        sender: Address,
        balance: u128,
        amount: u128,
    },
    #[error("issuing {amount} of {asset} would raise supply to {resulting}, over the cap of {cap}")]
    SupplyCapExceeded {
        asset: AssetRef,
        cap: u128,
        resulting: u128,
        amount: u128,
    },
    #[error("supply of {asset} would overflow u128")]
    SupplyOverflow { asset: AssetRef },
    #[error("{asset} is frozen: no transfers until it is unfrozen")]
    AssetFrozen { asset: AssetRef },
    #[error("{address} is frozen for {asset} and may neither send nor receive it")]
    HolderFrozen { asset: AssetRef, address: Address },
    #[error(
        "{sender} has {locked} of {asset} locked: only {available} of {balance} is spendable, needs {amount}"
    )]
    AmountLocked {
        asset: AssetRef,
        sender: Address,
        balance: u128,
        locked: u128,
        available: u128,
        amount: u128,
    },
    #[error(
        "cannot lock {amount} of {asset} for {holder}: balance is {balance}, already locked {locked}"
    )]
    LockExceedsBalance {
        asset: AssetRef,
        holder: Address,
        balance: u128,
        locked: u128,
        amount: u128,
    },
    #[error("cannot unlock {amount} of {asset} for {holder}: only {locked} is locked")]
    UnlockExceedsLocked {
        asset: AssetRef,
        holder: Address,
        locked: u128,
        amount: u128,
    },
    #[error("issuance of {asset} is locked")]
    IssuanceLocked { asset: AssetRef },
    #[error("burning {amount} of {asset} exceeds the issuer's balance of {balance}")]
    BurnExceedsBalance {
        asset: AssetRef,
        balance: u128,
        amount: u128,
    },
    /// Balance ≤ total_supply is an invariant every mint/transfer keeps; a
    /// burn that would take supply below zero means state is already
    /// corrupt, so refuse rather than silently clamp it.
    #[error("burning {amount} of {asset} exceeds its total supply of {total_supply}")]
    BurnExceedsSupply {
        asset: AssetRef,
        total_supply: u128,
        amount: u128,
    },
    #[error("{address} is missing the {topic:?} claim required by {asset}")]
    MissingClaim {
        asset: AssetRef,
        address: Address,
        topic: ClaimTopic,
    },
    #[error("{address}'s jurisdiction ({jurisdiction:?}) is not among those {asset} permits")]
    JurisdictionNotAllowed {
        asset: AssetRef,
        address: Address,
        jurisdiction: Option<CountryCode>,
    },
    #[error("{address}'s attestation is {age} blocks old, over {asset}'s limit of {max_age}")]
    AttestationExpired {
        asset: AssetRef,
        address: Address,
        age: u64,
        max_age: u64,
    },
    #[error("{asset} already has {holders} holders, the cap: {address} cannot become one")]
    HolderCapReached {
        asset: AssetRef,
        address: Address,
        holders: u32,
    },
    #[error("{address} would hold {resulting} of {asset}, over the per-holder limit of {limit}")]
    HolderLimitExceeded {
        asset: AssetRef,
        address: Address,
        resulting: u128,
        limit: u128,
    },
}

/// Sender-side result used by wallets before a recipient and amount have
/// been selected. The string values are part of the account-assets RPC
/// contract; add new reasons rather than renaming existing ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferEligibility {
    Eligible,
    AssetFrozen,
    HolderFrozen,
    MissingAttestation,
    MissingRequiredClaim,
    JurisdictionNotAllowed,
    AttestationExpired,
    NoTransferableBalance,
}

impl TransferEligibility {
    pub fn is_eligible(self) -> bool {
        self == Self::Eligible
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::AssetFrozen => "asset_frozen",
            Self::HolderFrozen => "holder_frozen",
            Self::MissingAttestation => "missing_attestation",
            Self::MissingRequiredClaim => "missing_required_claim",
            Self::JurisdictionNotAllowed => "jurisdiction_not_allowed",
            Self::AttestationExpired => "attestation_expired",
            Self::NoTransferableBalance => "no_transferable_balance",
        }
    }
}

/// Whether one party may hold `asset`, checked identically for sender and
/// recipient — a transfer is only compliant if both ends are.
///
/// `required_claims` is authoritative when non-empty, and `compliance_required`
/// is the fallback for assets registered before claim topics existed. They are
/// deliberately not both applied: an asset listing topics has already said
/// something more specific than "must be attested", and requiring the bool as
/// well would make it impossible to express topic gating without it.
pub use circuit_identity::is_attested;

fn check_party<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    party: &Address,
    current_height: u64,
) -> Result<(), RwaError> {
    let entry = view.get(&AccountKey(party))?;

    // An issuer-frozen holder is out of circulation in both directions,
    // whatever its claims say.
    if holder_state(view, asset, party, current_height)?.frozen {
        return Err(RwaError::HolderFrozen {
            asset: asset.asset_ref.clone(),
            address: party.clone(),
        });
    }

    if !asset.required_claims.is_empty() {
        // An attested account is still the baseline: topics qualify an
        // attestation, they don't substitute for having one.
        if !is_attested(view, party)? {
            return Err(RwaError::NotCompliant {
                address: party.clone(),
            });
        }
        let held = entry
            .as_ref()
            .map(|e| e.claims.as_slice())
            .unwrap_or_default();
        if let Some(missing) = asset.required_claims.iter().find(|t| !held.contains(t)) {
            return Err(RwaError::MissingClaim {
                asset: asset.asset_ref.clone(),
                address: party.clone(),
                topic: missing.clone(),
            });
        }
    } else if asset.compliance_required && !is_attested(view, party)? {
        return Err(RwaError::NotCompliant {
            address: party.clone(),
        });
    }

    // KYC goes stale. An attestation older than the asset allows is treated
    // like no attestation; one from before `attested_at` was recorded has
    // no age at all and is likewise rejected by an age-limited asset.
    if let Some(max_age) = asset.max_attestation_age {
        let attested_at = entry.as_ref().and_then(|e| e.attested_at);
        let age = attested_at.map(|at| current_height.saturating_sub(at));
        if age.is_none_or(|age| age > max_age) {
            return Err(RwaError::AttestationExpired {
                asset: asset.asset_ref.clone(),
                address: party.clone(),
                age: age.unwrap_or(u64::MAX),
                max_age,
            });
        }
    }

    // An unknown jurisdiction is rejected, not waved through: a restricted
    // asset can only be held where it is permitted, and "we don't know" is
    // not a permission.
    if let Some(allowed) = &asset.allowed_jurisdictions {
        let held = entry.as_ref().and_then(|e| e.jurisdiction.clone());
        if !held.as_ref().is_some_and(|code| allowed.contains(code)) {
            return Err(RwaError::JurisdictionNotAllowed {
                asset: asset.asset_ref.clone(),
                address: party.clone(),
                jurisdiction: held,
            });
        }
    }
    Ok(())
}

/// The recipient side of a compliant credit: `check_party`, then the two
/// prospectus limits. The issuer's own balance is exempt from both — it's
/// the treasury, not an investor. Returns the recipient's current balance so
/// the caller doesn't read it twice.
fn check_recipient<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<u128, RwaError> {
    check_party(view, asset, to, current_height)?;
    let balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: to,
        })?
        .unwrap_or(0);
    if to == &asset.issuer {
        return Ok(balance);
    }
    if let Some(cap) = asset.max_holders
        && balance == 0
        && amount > 0
        && asset.holder_count >= cap
    {
        return Err(RwaError::HolderCapReached {
            asset: asset.asset_ref.clone(),
            address: to.clone(),
            holders: asset.holder_count,
        });
    }
    if let Some(limit) = asset.max_balance_per_holder {
        let resulting = credit(&asset.asset_ref, balance, amount)?;
        if resulting > limit {
            return Err(RwaError::HolderLimitExceeded {
                asset: asset.asset_ref.clone(),
                address: to.clone(),
                resulting,
                limit,
            });
        }
    }
    Ok(balance)
}

/// Keeps `Asset.holder_count` in step with one balance moving from `before`
/// to `after`. The issuer never counts.
fn track_holder(asset: &mut Asset, who: &Address, before: u128, after: u128) {
    if who == &asset.issuer {
        return;
    }
    match (before == 0, after == 0) {
        (true, false) => asset.holder_count = asset.holder_count.saturating_add(1),
        (false, true) => asset.holder_count = asset.holder_count.saturating_sub(1),
        _ => {}
    }
}

/// Whether `sender` can make a positive compliant transfer to an otherwise
/// eligible recipient. This intentionally excludes recipient-specific and
/// nonce checks, which cannot be answered by an account-assets listing.
/// Gate ordering matches `apply_compliant_transfer`.
pub fn transfer_eligibility<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    sender: &Address,
    balance: u128,
    current_height: u64,
) -> Result<TransferEligibility, StorageError> {
    if asset.frozen {
        return Ok(TransferEligibility::AssetFrozen);
    }

    match check_party(view, asset, sender, current_height) {
        Ok(()) => {}
        Err(RwaError::Storage(err)) => return Err(err),
        Err(RwaError::HolderFrozen { .. }) => return Ok(TransferEligibility::HolderFrozen),
        Err(RwaError::NotCompliant { .. }) => return Ok(TransferEligibility::MissingAttestation),
        Err(RwaError::MissingClaim { .. }) => return Ok(TransferEligibility::MissingRequiredClaim),
        Err(RwaError::JurisdictionNotAllowed { .. }) => {
            return Ok(TransferEligibility::JurisdictionNotAllowed);
        }
        Err(RwaError::AttestationExpired { .. }) => {
            return Ok(TransferEligibility::AttestationExpired);
        }
        Err(_) => unreachable!("check_party returned an unrelated transfer error"),
    }

    let locked = holder_state(view, asset, sender, current_height)
        .map_err(|err| match err {
            RwaError::Storage(err) => err,
            _ => unreachable!("holder_state returned a non-storage error"),
        })?
        .frozen_amount;
    if balance.saturating_sub(locked) == 0 {
        return Ok(TransferEligibility::NoTransferableBalance);
    }

    Ok(TransferEligibility::Eligible)
}

/// Mints `amount` of `asset` into the issuer's own balance. `sender` must
/// equal `asset.issuer` — issuance is self-minting, not a transfer of
/// existing supply. `asset` is caller-resolved (not looked up here) so this
/// stays agnostic to whether the caller backs it with a real registry
/// (`arxd/runtime`'s `RegisterAsset`/`asset_record:{id}`) or a fixed in-memory
/// one (`examples/toy-chain`, which has no registry at all).
///
/// Mints into `AssetBalanceKey`, not `AccountEntry.balance` — that's the
/// whole point of the asset/native split: fees and staking (native balance)
/// never require KYC, only regulated-asset balances do. The sender's
/// `AccountEntry` is still touched, but only for its nonce.
///
/// Takes `asset` by `&mut` because `total_supply` is part of the asset record
/// and issuance is what moves it: returning the running total separately
/// would let a caller persist balances while forgetting the counter, and then
/// `max_supply` would never bind. Callers that keep a registry are expected
/// to write the mutated record back (`arxd/runtime`'s `issue_asset` puts it
/// through `BlockUpdates::asset_registration`); callers with a fixed
/// in-memory asset (`examples/toy-chain`) can simply drop it.
pub fn apply_issue<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    sender: &Address,
    nonce: u64,
    amount: u128,
) -> Result<(AccountUpdates, AssetBalanceUpdates), RwaError> {
    if sender != &asset.issuer {
        return Err(RwaError::NotIssuer {
            issuer: asset.issuer.clone(),
            sender: sender.clone(),
        });
    }

    if asset.issuance_locked {
        return Err(RwaError::IssuanceLocked {
            asset: asset.asset_ref.clone(),
        });
    }
    // Checked before any balance math so a rejected issue leaves nothing
    // half-applied. Overflow is its own error rather than a saturating
    // clamp: silently minting less than asked for is worse than failing.
    let resulting =
        asset
            .total_supply
            .checked_add(amount)
            .ok_or_else(|| RwaError::SupplyOverflow {
                asset: asset.asset_ref.clone(),
            })?;
    if let Some(cap) = asset.max_supply
        && resulting > cap
    {
        return Err(RwaError::SupplyCapExceeded {
            asset: asset.asset_ref.clone(),
            cap,
            resulting,
            amount,
        });
    }

    let mut entry = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        ..Default::default()
    });

    if nonce != entry.nonce {
        return Err(RwaError::InvalidNonce {
            sender: sender.clone(),
            expected: entry.nonce,
            got: nonce,
        });
    }
    entry.nonce += 1;

    let existing_balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: sender,
        })?
        .unwrap_or(0);

    asset.total_supply = resulting;

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), entry)]));
    let assets = AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), sender.clone()),
        credit(&asset.asset_ref, existing_balance, amount)?,
    )]));
    Ok((accounts, assets))
}

/// Transfers `amount` of `asset` from `sender` to `to`, gated on both parties
/// clearing `check_party` — claim topics and jurisdiction when the asset
/// specifies them, otherwise the older `compliance_required` KYC flag. An
/// asset that specifies neither moves freely, same as the native token.
/// Balance/nonce math mirrors `circuit_account::apply_transfer` but against
/// `AssetBalanceKey`, not `AccountEntry.balance`.
///
/// Takes `asset` by `&mut` for `holder_count` (see `track_holder`); callers
/// with a registry write the record back, as they already do for issuance.
pub fn apply_compliant_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    sender: &Address,
    nonce: u64,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<(AccountUpdates, AssetBalanceUpdates), RwaError> {
    // First gate, ahead of compliance and balance: a freeze is meant to stop
    // circulation outright, so it must not be bypassable by a transfer that
    // would have failed a later check anyway for a different reason.
    if asset.frozen {
        return Err(RwaError::AssetFrozen {
            asset: asset.asset_ref.clone(),
        });
    }

    check_party(view, asset, sender, current_height)?;
    check_recipient(view, asset, to, amount, current_height)?;

    let mut sender_account = view.get(&AccountKey(sender))?.unwrap_or(AccountEntry {
        balance: 0,
        ..Default::default()
    });
    if nonce != sender_account.nonce {
        return Err(RwaError::InvalidNonce {
            sender: sender.clone(),
            expected: sender_account.nonce,
            got: nonce,
        });
    }
    sender_account.nonce += 1;

    // Partially frozen units stay put under a compliant transfer; only a
    // forced transfer or recovery moves them.
    let locked = holder_state(view, asset, sender, current_height)?.frozen_amount;
    if locked > 0 {
        let balance = view
            .get(&AssetBalanceKey {
                asset: &asset.asset_ref,
                owner: sender,
            })?
            .unwrap_or(0);
        let available = balance.saturating_sub(locked);
        if amount > available {
            return Err(RwaError::AmountLocked {
                asset: asset.asset_ref.clone(),
                sender: sender.clone(),
                balance,
                locked,
                available,
                amount,
            });
        }
    }

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), sender_account)]));
    let assets = apply_forced_transfer(view, asset, sender, to, amount)?;
    Ok((accounts, assets))
}

/// Supply created straight into a verified investor's
/// balance. `to` must pass the asset's rules; the issuer is not checked —
/// it never holds the units, which is the point for an issuer that is not
/// itself an attested party. Nonce handling is left to the runtime's generic
/// discipline (`consume_nonce`).
pub fn apply_issue_to<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<AssetBalanceUpdates, RwaError> {
    if asset.issuance_locked {
        return Err(RwaError::IssuanceLocked {
            asset: asset.asset_ref.clone(),
        });
    }
    if asset.frozen {
        return Err(RwaError::AssetFrozen {
            asset: asset.asset_ref.clone(),
        });
    }
    let existing = check_recipient(view, asset, to, amount, current_height)?;
    let resulting =
        asset
            .total_supply
            .checked_add(amount)
            .ok_or_else(|| RwaError::SupplyOverflow {
                asset: asset.asset_ref.clone(),
            })?;
    if let Some(cap) = asset.max_supply
        && resulting > cap
    {
        return Err(RwaError::SupplyCapExceeded {
            asset: asset.asset_ref.clone(),
            cap,
            resulting,
            amount,
        });
    }
    asset.total_supply = resulting;
    let credited = credit(&asset.asset_ref, existing, amount)?;
    track_holder(asset, to, existing, credited);
    Ok(AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), to.clone()),
        credited,
    )])))
}

/// The holder's state as it binds at `current_height`: an expired
/// `lock_expires_at` reads as no lock. The stored record is left as-is —
/// the next write through `apply_lock_amount` clears it.
fn holder_state<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    holder: &Address,
    current_height: u64,
) -> Result<HolderState, RwaError> {
    let mut state = view
        .get(&AssetHolderStateKey {
            asset: &asset.asset_ref,
            holder,
        })?
        .unwrap_or_default();
    if state.lock_expires_at.is_some_and(|at| current_height >= at) {
        state.frozen_amount = 0;
        state.lock_expires_at = None;
    }
    Ok(state)
}

/// A balance credit. Every credit is already bounded by `total_supply`'s
/// own `checked_add`, but that argument lives in a different variable —
/// keep the overflow check local so it doesn't have to be reconstructed.
fn credit(asset: &AssetRef, balance: u128, amount: u128) -> Result<u128, RwaError> {
    balance
        .checked_add(amount)
        .ok_or_else(|| RwaError::SupplyOverflow {
            asset: asset.clone(),
        })
}

/// Issuer burns `amount` from its own balance; `total_supply` follows. Only
/// the issuer's own units can be destroyed — pulling supply back from a
/// holder is a forced transfer to the issuer first, on purpose, so the
/// on-chain record shows both steps.
pub fn apply_burn<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    issuer: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, RwaError> {
    let balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: issuer,
        })?
        .unwrap_or(0);
    if amount > balance {
        return Err(RwaError::BurnExceedsBalance {
            asset: asset.asset_ref.clone(),
            balance,
            amount,
        });
    }
    asset.total_supply =
        asset
            .total_supply
            .checked_sub(amount)
            .ok_or_else(|| RwaError::BurnExceedsSupply {
                asset: asset.asset_ref.clone(),
                total_supply: asset.total_supply,
                amount,
            })?;
    Ok(AssetBalanceUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), issuer.clone()),
        balance - amount,
    )])))
}

/// Address freeze: the whole holder in or out of circulation.
pub fn apply_set_holder_frozen<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    holder: &Address,
    frozen: bool,
) -> Result<HolderStateUpdates, RwaError> {
    // Raw read on purpose: an address freeze must not silently drop a lock
    // that happens to have expired — that's `apply_lock_amount`'s job.
    let mut state = view
        .get(&AssetHolderStateKey {
            asset: &asset.asset_ref,
            holder,
        })?
        .unwrap_or_default();
    state.frozen = frozen;
    Ok(HolderStateUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), holder.clone()),
        state,
    )])))
}

/// Partial lock / unlock: lock or release
/// `amount` units of `holder`'s balance. A lock may never exceed the balance,
/// an unlock never the locked amount.
///
/// `expires_at` (lock only) makes the lock self-releasing at that height. One
/// expiry per holder: locking again replaces it, so the latest lock's term
/// governs the whole locked amount — an open-ended lock over an expiring one
/// clears the expiry. Expired locks are dropped before the arithmetic.
pub fn apply_lock_amount<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    holder: &Address,
    amount: u128,
    lock: bool,
    expires_at: Option<u64>,
    current_height: u64,
) -> Result<HolderStateUpdates, RwaError> {
    let mut state = holder_state(view, asset, holder, current_height)?;
    if lock {
        let balance = view
            .get(&AssetBalanceKey {
                asset: &asset.asset_ref,
                owner: holder,
            })?
            .unwrap_or(0);
        let resulting = state.frozen_amount.saturating_add(amount);
        if resulting > balance {
            return Err(RwaError::LockExceedsBalance {
                asset: asset.asset_ref.clone(),
                holder: holder.clone(),
                balance,
                locked: state.frozen_amount,
                amount,
            });
        }
        state.frozen_amount = resulting;
        state.lock_expires_at = expires_at;
    } else {
        if amount > state.frozen_amount {
            return Err(RwaError::UnlockExceedsLocked {
                asset: asset.asset_ref.clone(),
                holder: holder.clone(),
                locked: state.frozen_amount,
                amount,
            });
        }
        state.frozen_amount -= amount;
        if state.frozen_amount == 0 {
            state.lock_expires_at = None;
        }
    }
    Ok(HolderStateUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), holder.clone()),
        state,
    )])))
}

/// Wallet recovery: move everything `lost` holds of `asset` — balance
/// and freeze state alike — to `replacement`, which must itself pass the
/// asset's compliance rules (a lost wallet is not a way around KYC). The lost
/// wallet is left with nothing and a clean state.
pub fn apply_recover<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    lost: &Address,
    replacement: &Address,
    current_height: u64,
) -> Result<(AssetBalanceUpdates, HolderStateUpdates), RwaError> {
    let lost_balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: lost,
        })?
        .unwrap_or(0);
    let replacement_balance =
        check_recipient(view, asset, replacement, lost_balance, current_height)?;
    let lost_state = holder_state(view, asset, lost, current_height)?;
    let mut replacement_state = holder_state(view, asset, replacement, current_height)?;
    replacement_state.frozen_amount = replacement_state
        .frozen_amount
        .saturating_add(lost_state.frozen_amount);
    // The later expiry wins so neither lock is shortened by the merge.
    replacement_state.lock_expires_at = match (
        replacement_state.lock_expires_at,
        lost_state.lock_expires_at,
    ) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let recovered = replacement_balance.saturating_add(lost_balance);
    track_holder(asset, lost, lost_balance, 0);
    track_holder(asset, replacement, replacement_balance, recovered);
    // The address freeze travels too: recovery moves a holder,
    // it doesn't launder a frozen one.
    replacement_state.frozen |= lost_state.frozen;
    let id = asset.asset_ref.clone();
    Ok((
        AssetBalanceUpdates(BTreeMap::from([
            ((id.clone(), lost.clone()), 0),
            ((id.clone(), replacement.clone()), recovered),
        ])),
        HolderStateUpdates(BTreeMap::from([
            ((id.clone(), lost.clone()), HolderState::default()),
            ((id, replacement.clone()), replacement_state),
        ])),
    ))
}

/// Moves `amount` of `asset` from `from` to `to` with no compliance, freeze or
/// nonce gate — only the balance check, so it can never mint.
///
/// This is deliberately the unchecked mover, and it is both the tail of
/// `apply_compliant_transfer` (which runs every gate before calling it) and
/// the whole of `ForcedTransfer`. `ForcedTransfer` exists for the cases
/// compliance cannot express — a court order, a sanctioned holder, a lost
/// key — where the holder cannot or must not sign, and where the recipient's
/// claims may well be the reason the transfer is being forced. Freeze is
/// likewise not a gate here: freezing an instrument is exactly when a
/// regulator most needs to be able to move it. Authorization is the caller's
/// job (the runtime restricts `ForcedTransfer` to the recovery admin); this
/// function assumes it has already been established.
pub fn apply_forced_transfer<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Result<AssetBalanceUpdates, RwaError> {
    let from_balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: from,
        })?
        .unwrap_or(0);
    if from_balance < amount {
        return Err(RwaError::InsufficientBalance {
            asset: asset.asset_ref.clone(),
            sender: from.clone(),
            balance: from_balance,
            amount,
        });
    }

    // ponytail: self-transfer is balance-neutral (would otherwise read its
    // own not-yet-applied debit as the credit) — mirrors
    // `circuit_account::apply_transfer`'s same special case.
    if to == from {
        return Ok(AssetBalanceUpdates(BTreeMap::new()));
    }

    let to_balance = view
        .get(&AssetBalanceKey {
            asset: &asset.asset_ref,
            owner: to,
        })?
        .unwrap_or(0);

    let to_after = credit(&asset.asset_ref, to_balance, amount)?;
    track_holder(asset, from, from_balance, from_balance - amount);
    track_holder(asset, to, to_balance, to_after);
    Ok(AssetBalanceUpdates(BTreeMap::from([
        (
            (asset.asset_ref.clone(), from.clone()),
            from_balance - amount,
        ),
        ((asset.asset_ref.clone(), to.clone()), to_after),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_storage::{ArxiumDb, HolderStateUpdates};

    fn temp_db() -> ArxiumDb {
        let path = std::env::temp_dir().join(format!("arxium-test-rwa-{}", uuid_like()));
        ArxiumDb::open(&path).unwrap()
    }

    fn uuid_like() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nanos + COUNTER.fetch_add(1, Ordering::Relaxed) as u128
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    /// Seeds an unrestricted (non-compliance) asset with `issuer` holding
    /// `supply`, so the holder-control tests exercise only the new gates.
    fn seeded_open_asset(db: &ArxiumDb, issuer: &Address, supply: u128) -> Asset {
        let mut asset = Asset::new("gold", issuer.clone(), false);
        let (accounts, assets) = apply_issue(db, &mut asset, issuer, 0, supply).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();
        asset
    }

    #[test]
    fn sender_eligibility_matches_transfer_policy() {
        let db = temp_db();
        let holder = addr(2);
        let mut asset = Asset::new("bond", addr(1), false);
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::Eligible
        );

        asset.frozen = true;
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::AssetFrozen
        );
        asset.frozen = false;
        db.write_batch(&HolderStateUpdates(BTreeMap::from([(
            (asset.asset_ref.clone(), holder.clone()),
            HolderState {
                frozen: true,
                frozen_amount: 10,
                lock_expires_at: None,
            },
        )])))
        .unwrap();
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::HolderFrozen
        );
        db.write_batch(&HolderStateUpdates(BTreeMap::from([(
            (asset.asset_ref.clone(), holder.clone()),
            HolderState {
                frozen: false,
                frozen_amount: 10,
                lock_expires_at: None,
            },
        )])))
        .unwrap();
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::NoTransferableBalance
        );

        db.write_batch(&HolderStateUpdates(BTreeMap::from([(
            (asset.asset_ref.clone(), holder.clone()),
            HolderState::default(),
        )])))
        .unwrap();
        asset.compliance_required = true;
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::MissingAttestation
        );
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            holder.clone(),
            AccountEntry {
                identity_hash: Some("kyc".into()),
                attested_by: Some(addr(9)),
                ..Default::default()
            },
        )])))
        .unwrap();
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::MissingAttestation
        );

        attest(&db, &holder, &[], None);
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::Eligible
        );
        asset.required_claims = vec![ClaimTopic::Kyc];
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::MissingRequiredClaim
        );
        attest(&db, &holder, &[ClaimTopic::Kyc], None);
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::Eligible
        );

        asset.allowed_jurisdictions = Some(Vec::new());
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::JurisdictionNotAllowed
        );
        asset.allowed_jurisdictions = None;
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 10, 0).unwrap(),
            TransferEligibility::Eligible
        );
    }

    #[test]
    fn compliant_transfer_rejects_an_attestation_from_an_inactive_attestor() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        let (accounts, balances) = apply_issue(&db, &mut asset, &issuer, 0, 10).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&balances).unwrap();
        for address in [&issuer, &recipient] {
            db.write_batch(&AccountUpdates(BTreeMap::from([(
                address.clone(),
                AccountEntry {
                    identity_hash: Some("kyc".into()),
                    attested_by: Some(addr(9)),
                    nonce: u64::from(address == &issuer),
                    ..Default::default()
                },
            )])))
            .unwrap();
        }

        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 1, 0).unwrap_err();
        assert!(
            matches!(&err, RwaError::NotCompliant { address } if address == &issuer),
            "got: {err}"
        );
    }

    #[test]
    fn a_frozen_holder_can_neither_send_nor_receive_but_forced_transfer_still_moves_it() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 40, 0).unwrap();
        db.write_batch(&assets).unwrap();

        db.write_batch(&apply_set_holder_frozen(&db, &asset, &holder, true).unwrap())
            .unwrap();
        let err =
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 10, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::HolderFrozen { .. }),
            "frozen holder cannot send: {err}"
        );
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 2, &holder, 10, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::HolderFrozen { .. }),
            "frozen holder cannot receive: {err}"
        );

        let assets = apply_forced_transfer(&db, &mut asset, &holder, &issuer, 40).unwrap();
        assert_eq!(
            assets.0[&(asset.asset_ref.clone(), holder.clone())],
            0,
            "forced transfer ignores the freeze"
        );

        db.write_batch(&apply_set_holder_frozen(&db, &asset, &holder, false).unwrap())
            .unwrap();
        assert!(
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 10, 0).is_ok(),
            "unfrozen holder sends again"
        );
    }

    #[test]
    fn locked_units_are_unspendable_under_compliant_transfer_and_bounded_by_balance() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 50, 0).unwrap();
        db.write_batch(&assets).unwrap();

        let err = apply_lock_amount(&db, &asset, &holder, 60, true, None, 0).unwrap_err();
        assert!(matches!(err, RwaError::LockExceedsBalance { .. }), "{err}");
        db.write_batch(&apply_lock_amount(&db, &asset, &holder, 30, true, None, 0).unwrap())
            .unwrap();

        let err =
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 25, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::AmountLocked { available: 20, .. }),
            "{err}"
        );
        assert!(
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 20, 0).is_ok(),
            "the unlocked 20 spend"
        );

        let err = apply_lock_amount(&db, &asset, &holder, 31, false, None, 0).unwrap_err();
        assert!(matches!(err, RwaError::UnlockExceedsLocked { .. }), "{err}");
        db.write_batch(&apply_lock_amount(&db, &asset, &holder, 30, false, None, 0).unwrap())
            .unwrap();
        assert!(
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 50, 0).is_ok(),
            "everything spendable again"
        );
    }

    #[test]
    fn issue_to_mints_into_a_compliant_recipient_and_respects_the_cap() {
        let db = temp_db();
        let issuer = addr(1);
        let investor = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);
        asset.max_supply = Some(100);

        // Issuer is not attested; that must not matter. Investor is not yet: refused.
        let err = apply_issue_to(&db, &mut asset, &investor, 40, 0).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "{err}");
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            investor.clone(),
            AccountEntry {
                identity_hash: Some("kyc".into()),
                ..Default::default()
            },
        )])))
        .unwrap();
        let assets = apply_issue_to(&db, &mut asset, &investor, 40, 0).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), investor.clone())], 40);
        assert_eq!(asset.total_supply, 40);
        let err = apply_issue_to(&db, &mut asset, &investor, 61, 0).unwrap_err();
        assert!(matches!(err, RwaError::SupplyCapExceeded { .. }), "{err}");
    }

    /// The burn-then-remint hole: under a cap, a burn frees room that a
    /// fresh issue can refill. `issuance_locked` is what closes it.
    #[test]
    fn locked_issuance_refuses_every_mint_after_a_burn() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        asset.max_supply = Some(100);
        apply_burn(&db, &mut asset, &issuer, 50).unwrap();
        assert_eq!(asset.total_supply, 50);
        // Unlocked: the burn reopened cap room, as on every other chain.
        apply_issue(&db, &mut asset, &issuer, 1, 10).unwrap();
        asset.issuance_locked = true;
        let err = apply_issue(&db, &mut asset, &issuer, 2, 1).unwrap_err();
        assert!(matches!(err, RwaError::IssuanceLocked { .. }), "{err}");
        let err = apply_issue_to(&db, &mut asset, &issuer, 1, 0).unwrap_err();
        assert!(matches!(err, RwaError::IssuanceLocked { .. }), "{err}");
        assert_eq!(asset.total_supply, 60, "a refused issue moves nothing");
    }

    #[test]
    fn burn_reduces_supply_and_only_from_the_issuer_balance() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        let assets = apply_burn(&db, &mut asset, &issuer, 30).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), issuer.clone())], 70);
        assert_eq!(asset.total_supply, 70);
        let err = apply_burn(&db, &mut asset, &issuer, 101).unwrap_err();
        assert!(matches!(err, RwaError::BurnExceedsBalance { .. }), "{err}");

        // Corrupt supply (below the issuer's own balance) is refused, not clamped to 0.
        asset.total_supply = 10;
        let err = apply_burn(&db, &mut asset, &issuer, 20).unwrap_err();
        assert!(
            matches!(
                err,
                RwaError::BurnExceedsSupply {
                    total_supply: 10,
                    amount: 20,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(asset.total_supply, 10);
    }

    #[test]
    fn recovery_moves_balance_and_lock_to_a_compliant_replacement_only() {
        let db = temp_db();
        let issuer = addr(1);
        let lost = addr(2);
        let replacement = addr(3);
        let mut asset = Asset::new("gold", issuer.clone(), true);
        db.write_batch(&AccountUpdates(BTreeMap::from([
            (
                issuer.clone(),
                AccountEntry {
                    identity_hash: Some("kyc".into()),
                    ..Default::default()
                },
            ),
            (
                lost.clone(),
                AccountEntry {
                    identity_hash: Some("kyc".into()),
                    ..Default::default()
                },
            ),
        ])))
        .unwrap();
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();
        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &lost, 60, 0).unwrap();
        db.write_batch(&assets).unwrap();
        db.write_batch(&apply_lock_amount(&db, &asset, &lost, 15, true, None, 0).unwrap())
            .unwrap();

        // Replacement is not attested: recovery must not become a KYC bypass.
        let err = apply_recover(&db, &mut asset, &lost, &replacement, 0).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "{err}");

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            replacement.clone(),
            AccountEntry {
                identity_hash: Some("kyc".into()),
                ..Default::default()
            },
        )])))
        .unwrap();
        let (assets, states) = apply_recover(&db, &mut asset, &lost, &replacement, 0).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), lost.clone())], 0);
        assert_eq!(
            assets.0[&(asset.asset_ref.clone(), replacement.clone())],
            60
        );
        assert_eq!(
            states.0[&(asset.asset_ref.clone(), replacement.clone())].frozen_amount,
            15,
            "the lock travels with the balance"
        );
        assert!(!states.0[&(asset.asset_ref.clone(), replacement.clone())].frozen);
        assert_eq!(
            states.0[&(asset.asset_ref.clone(), lost.clone())],
            HolderState::default()
        );

        // A frozen lost wallet recovers into a frozen replacement.
        db.write_batch(&apply_set_holder_frozen(&db, &asset, &lost, true).unwrap())
            .unwrap();
        let (_, states) = apply_recover(&db, &mut asset, &lost, &replacement, 0).unwrap();
        assert!(
            states.0[&(asset.asset_ref.clone(), replacement.clone())].frozen,
            "the address freeze travels too"
        );
    }

    #[test]
    fn issue_mints_asset_balance_not_native_balance_and_rejects_non_issuers() {
        let db = temp_db();
        let issuer = addr(1);
        let other = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 1000).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), issuer.clone())], 1000);
        assert_eq!(
            accounts.0[&issuer].balance, 0,
            "issue must not touch the native balance"
        );
        assert_eq!(accounts.0[&issuer].nonce, 1);

        assert_eq!(
            asset.total_supply, 1000,
            "issuance tracks cumulative supply"
        );

        let err = apply_issue(&db, &mut asset, &other, 0, 1000).unwrap_err();
        assert!(matches!(err, RwaError::NotIssuer { .. }));
    }

    #[test]
    fn compliant_transfer_fails_without_recipient_attestation_and_succeeds_after() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            issuer.clone(),
            AccountEntry {
                identity_hash: Some("kyc-issuer".into()),
                ..Default::default()
            },
        )])))
        .unwrap();
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Recipient has no identity_hash yet — the demo: fails.
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 40, 0).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }));

        // Attestor grants recipient an attestation — now it succeeds.
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            recipient.clone(),
            AccountEntry {
                identity_hash: Some("kyc-recipient".into()),
                ..Default::default()
            },
        )])))
        .unwrap();
        let (accounts, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 40, 0).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), recipient.clone())], 40);
        assert_eq!(assets.0[&(asset.asset_ref.clone(), issuer.clone())], 60);
        assert_eq!(accounts.0[&issuer].nonce, 2);
    }

    #[test]
    fn issue_respects_max_supply_across_repeated_issuance() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("capped", issuer.clone(), false);
        asset.max_supply = Some(100);

        // Two issues that together exactly reach the cap are both fine —
        // the check is on the running total, not per-action.
        apply_issue(&db, &mut asset, &issuer, 0, 60).unwrap();
        assert_eq!(asset.total_supply, 60);
        apply_issue(&db, &mut asset, &issuer, 0, 40).unwrap();
        assert_eq!(asset.total_supply, 100);

        // One more unit is over.
        let err = apply_issue(&db, &mut asset, &issuer, 0, 1).unwrap_err();
        assert!(
            matches!(
                &err,
                RwaError::SupplyCapExceeded {
                    cap: 100,
                    resulting: 101,
                    ..
                }
            ),
            "got: {err}"
        );
        assert_eq!(
            asset.total_supply, 100,
            "a rejected issue must not move the counter"
        );
    }

    #[test]
    fn issue_rejects_a_supply_overflow_rather_than_wrapping() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("uncapped", issuer.clone(), false);
        asset.total_supply = u128::MAX - 1;

        let err = apply_issue(&db, &mut asset, &issuer, 0, 2).unwrap_err();
        assert!(matches!(err, RwaError::SupplyOverflow { .. }), "got: {err}");
        assert_eq!(asset.total_supply, u128::MAX - 1);
    }

    /// The freeze gate runs ahead of the compliance and balance checks, so it
    /// reports `AssetFrozen` even for a transfer that would also have failed
    /// for another reason — otherwise a frozen asset's error message would
    /// depend on which other check happened to trip first.
    #[test]
    fn a_frozen_asset_blocks_transfers_ahead_of_every_other_check() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("gold", issuer.clone(), true);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        asset.frozen = true;
        // Un-KYC'd recipient *and* a wrong nonce *and* an over-balance amount:
        // still reports the freeze.
        let err = apply_compliant_transfer(&db, &mut asset, &issuer, 99, &recipient, 10_000, 0)
            .unwrap_err();
        assert!(matches!(err, RwaError::AssetFrozen { .. }), "got: {err}");

        asset.frozen = false;
        let err = apply_compliant_transfer(&db, &mut asset, &issuer, 99, &recipient, 10_000, 0)
            .unwrap_err();
        assert!(
            !matches!(err, RwaError::AssetFrozen { .. }),
            "unfrozen, so some other check should trip"
        );
    }

    /// Issuance is deliberately still allowed while frozen — a freeze stops
    /// circulation, it does not seal the supply.
    #[test]
    fn a_frozen_asset_can_still_be_issued() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("gold", issuer.clone(), true);
        asset.frozen = true;

        apply_issue(&db, &mut asset, &issuer, 0, 50).unwrap();
        assert_eq!(asset.total_supply, 50);
    }

    /// Seeds an attested account with the given claim topics and jurisdiction.
    fn attest(db: &ArxiumDb, who: &Address, claims: &[ClaimTopic], jurisdiction: Option<&str>) {
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            who.clone(),
            AccountEntry {
                identity_hash: Some(format!("kyc-{who}")),
                claims: claims.to_vec(),
                jurisdiction: jurisdiction.map(str::to_string),
                ..Default::default()
            },
        )])))
        .unwrap();
    }

    /// Both ends of a transfer must carry every required topic — a compliant
    /// sender cannot push a restricted asset to an under-claimed recipient.
    #[test]
    fn required_claims_are_enforced_on_both_parties() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc, ClaimTopic::Accredited];

        attest(
            &db,
            &issuer,
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            None,
        );
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Recipient is attested and KYC'd but not Accredited.
        attest(&db, &recipient, &[ClaimTopic::Kyc], None);
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(
            matches!(&err, RwaError::MissingClaim { topic: ClaimTopic::Accredited, address, .. } if address == &recipient),
            "got: {err}"
        );

        attest(
            &db,
            &recipient,
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            None,
        );
        apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0)
            .expect("both parties now hold every required claim");
    }

    /// A forced transfer walks through every gate a compliant transfer stops
    /// at — freeze, claims, jurisdiction, and the holder's own signature —
    /// because the situations it exists for are exactly the ones compliance
    /// refuses. The one thing it cannot do is create supply.
    #[test]
    fn forced_transfer_ignores_freeze_and_claims_but_cannot_mint() {
        let db = temp_db();
        let issuer = addr(1);
        let seized_from = addr(2);
        let receiver = addr(3);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc, ClaimTopic::Accredited];
        asset.allowed_jurisdictions = Some(vec!["CH".into()]);

        attest(
            &db,
            &issuer,
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            Some("CH"),
        );
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        attest(
            &db,
            &seized_from,
            &[ClaimTopic::Kyc, ClaimTopic::Accredited],
            Some("CH"),
        );
        let (accounts, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &seized_from, 60, 0).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Freeze the asset and leave the receiver with no attestation at all:
        // a compliant transfer has two independent reasons to refuse here.
        asset.frozen = true;
        let err = apply_compliant_transfer(&db, &mut asset, &seized_from, 1, &receiver, 60, 0)
            .unwrap_err();
        assert!(matches!(err, RwaError::AssetFrozen { .. }), "got: {err}");

        let moved = apply_forced_transfer(&db, &mut asset, &seized_from, &receiver, 60).unwrap();
        assert_eq!(moved.0[&(asset.asset_ref.clone(), seized_from.clone())], 0);
        assert_eq!(moved.0[&(asset.asset_ref.clone(), receiver.clone())], 60);

        // The balance check is the floor a governor cannot go under: forcing
        // more than the holder has would be minting by another name.
        let err = apply_forced_transfer(&db, &mut asset, &seized_from, &receiver, 61).unwrap_err();
        assert!(
            matches!(
                err,
                RwaError::InsufficientBalance {
                    balance: 60,
                    amount: 61,
                    ..
                }
            ),
            "got: {err}"
        );
    }

    /// Topics qualify an attestation rather than replacing it: holding the
    /// claims with no `identity_hash` is still not compliant.
    #[test]
    fn required_claims_still_need_an_underlying_attestation() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.required_claims = vec![ClaimTopic::Kyc];

        attest(&db, &issuer, &[ClaimTopic::Kyc], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        db.write_batch(&AccountUpdates(BTreeMap::from([(
            recipient.clone(),
            AccountEntry {
                claims: vec![ClaimTopic::Kyc],
                ..Default::default()
            },
        )])))
        .unwrap();
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "got: {err}");
    }

    /// A non-empty `required_claims` takes over from `compliance_required`
    /// rather than stacking with it, so an asset can gate on topics alone.
    #[test]
    fn required_claims_supersede_the_compliance_required_flag() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), false);
        asset.required_claims = vec![ClaimTopic::Aml];

        attest(&db, &issuer, &[ClaimTopic::Aml], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // `compliance_required` is false, but the topic list still binds.
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(matches!(err, RwaError::NotCompliant { .. }), "got: {err}");

        attest(&db, &recipient, &[ClaimTopic::Aml], None);
        apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap();
    }

    /// An unknown jurisdiction is a rejection, not a pass — the interesting
    /// half of the restriction, since the permissive reading would silently
    /// let unattributed holders through.
    #[test]
    fn jurisdiction_restriction_rejects_both_disallowed_and_unknown() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("reit", issuer.clone(), true);
        asset.allowed_jurisdictions = Some(vec!["CH".into(), "DE".into()]);

        attest(&db, &issuer, &[], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        // Attested, but jurisdiction unknown.
        attest(&db, &recipient, &[], None);
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(
            matches!(&err, RwaError::JurisdictionNotAllowed { jurisdiction: None, address, .. } if address == &recipient),
            "got: {err}"
        );

        // Known, but not permitted.
        attest(&db, &recipient, &[], Some("US"));
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(
            matches!(&err, RwaError::JurisdictionNotAllowed { jurisdiction: Some(j), .. } if j == "US"),
            "got: {err}"
        );

        attest(&db, &recipient, &[], Some("DE"));
        apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap();
    }

    /// `Some(vec![])` means nobody may hold it, and is distinct from `None`.
    #[test]
    fn an_empty_jurisdiction_allowlist_permits_nobody() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = Asset::new("sealed", issuer.clone(), false);

        attest(&db, &issuer, &[], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        asset.allowed_jurisdictions = Some(Vec::new());
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &addr(2), 10, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::JurisdictionNotAllowed { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn transfer_of_a_non_compliance_required_asset_skips_the_kyc_check() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("open", issuer.clone(), false);

        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap();
        assert_eq!(assets.0[&(asset.asset_ref.clone(), recipient)], 10);
    }

    /// Investor cap: the third distinct holder is refused, the issuer's own
    /// balance never counts, and a holder going to zero frees a slot.
    #[test]
    fn holder_cap_counts_non_issuer_addresses_with_a_positive_balance() {
        let db = temp_db();
        let issuer = addr(1);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        asset.max_holders = Some(2);
        assert_eq!(asset.holder_count, 0, "issuer's own supply is not a holder");

        for (nonce, who) in [(1, addr(2)), (2, addr(3))] {
            let (accounts, assets) =
                apply_compliant_transfer(&db, &mut asset, &issuer, nonce, &who, 10, 0).unwrap();
            db.write_batch(&accounts).unwrap();
            db.write_batch(&assets).unwrap();
        }
        assert_eq!(asset.holder_count, 2);
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 3, &addr(4), 10, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::HolderCapReached { holders: 2, .. }),
            "{err}"
        );
        // Topping up an existing holder is not a new holder.
        assert!(apply_compliant_transfer(&db, &mut asset, &issuer, 3, &addr(2), 10, 0).is_ok());

        // Forced out of circulation: the slot reopens, and a forced transfer
        // into a fresh address bypasses the cap but still counts.
        let assets = apply_forced_transfer(&db, &mut asset, &addr(3), &issuer, 10).unwrap();
        db.write_batch(&assets).unwrap();
        assert_eq!(asset.holder_count, 1);
        assert!(apply_compliant_transfer(&db, &mut asset, &issuer, 3, &addr(4), 10, 0).is_ok());
        let assets = apply_forced_transfer(&db, &mut asset, &issuer, &addr(5), 10).unwrap();
        db.write_batch(&assets).unwrap();
        assert_eq!(
            asset.holder_count, 3,
            "forced transfers keep the count honest"
        );
        assert!(matches!(
            apply_issue_to(&db, &mut asset, &addr(6), 1, 0).unwrap_err(),
            RwaError::HolderCapReached { .. }
        ));
    }

    #[test]
    fn per_holder_limit_caps_the_resulting_balance_not_the_amount() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        asset.max_balance_per_holder = Some(25);
        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 20, 0).unwrap();
        db.write_batch(&assets).unwrap();
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 10, 0).unwrap_err();
        assert!(
            matches!(
                err,
                RwaError::HolderLimitExceeded {
                    resulting: 30,
                    limit: 25,
                    ..
                }
            ),
            "{err}"
        );
        assert!(apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 5, 0).is_ok());
        // The issuer's treasury is exempt: units can always flow back.
        let assets = apply_forced_transfer(&db, &mut asset, &issuer, &holder, 5).unwrap();
        db.write_batch(&assets).unwrap();
        assert!(apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 25, 0).is_ok());
    }

    /// An attestation is only good for `max_attestation_age` blocks; one with
    /// no recorded height is already stale to an age-limited asset.
    #[test]
    fn attestation_expiry_is_measured_from_attested_at() {
        let db = temp_db();
        let issuer = addr(1);
        let recipient = addr(2);
        let mut asset = Asset::new("bond", issuer.clone(), true);
        asset.max_attestation_age = Some(100);
        attest(&db, &issuer, &[], None);
        attest(&db, &recipient, &[], None);
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();

        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 0).unwrap_err();
        assert!(
            matches!(err, RwaError::AttestationExpired { .. }),
            "no attested_at: {err}"
        );

        for who in [&issuer, &recipient] {
            let mut entry = db.get_account(who).unwrap().unwrap();
            entry.attested_at = Some(50);
            db.write_batch(&AccountUpdates(BTreeMap::from([(who.clone(), entry)])))
                .unwrap();
        }
        assert!(apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 150).is_ok());
        let err =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 151).unwrap_err();
        assert!(
            matches!(
                err,
                RwaError::AttestationExpired {
                    age: 101,
                    max_age: 100,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            transfer_eligibility(&db, &asset, &issuer, 10, 151).unwrap(),
            TransferEligibility::AttestationExpired
        );
        asset.max_attestation_age = None;
        assert!(
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &recipient, 10, 9_999).is_ok()
        );
    }

    #[test]
    fn a_lock_with_an_expiry_releases_itself_at_that_height() {
        let db = temp_db();
        let issuer = addr(1);
        let holder = addr(2);
        let mut asset = seeded_open_asset(&db, &issuer, 100);
        let (_, assets) =
            apply_compliant_transfer(&db, &mut asset, &issuer, 1, &holder, 50, 0).unwrap();
        db.write_batch(&assets).unwrap();
        db.write_batch(&apply_lock_amount(&db, &asset, &holder, 50, true, Some(200), 10).unwrap())
            .unwrap();

        let err =
            apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 1, 199).unwrap_err();
        assert!(
            matches!(err, RwaError::AmountLocked { locked: 50, .. }),
            "{err}"
        );
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 50, 199).unwrap(),
            TransferEligibility::NoTransferableBalance
        );
        assert!(apply_compliant_transfer(&db, &mut asset, &holder, 0, &issuer, 50, 200).is_ok());
        assert_eq!(
            transfer_eligibility(&db, &asset, &holder, 50, 200).unwrap(),
            TransferEligibility::Eligible
        );
        // Re-locking after expiry starts from zero, not from the stale 50.
        let states = apply_lock_amount(&db, &asset, &holder, 10, true, None, 200).unwrap();
        let state = &states.0[&(asset.asset_ref.clone(), holder.clone())];
        assert_eq!((state.frozen_amount, state.lock_expires_at), (10, None));
    }
}
