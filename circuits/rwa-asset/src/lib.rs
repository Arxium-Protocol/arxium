// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{
    AccountKey, AssetBalanceKey, AssetHolderStateKey, AssetHoldersKey, ChainParamsKey, KeySpec,
    KvRead,
};
use xc_primitives::{
    AccountEntry, Address, Asset, AssetRef, CapTable, ClaimTopic, CountryCode, HolderState,
};
use xc_storage::{
    AccountUpdates, AssetBalanceUpdates, BatchWritable, HolderStateUpdates, StorageError,
};

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
    #[error("pro-rata arithmetic for {asset} overflows u128")]
    ShareOverflow { asset: AssetRef },
}

impl RwaError {
    /// The party a compliance-family error is about, when it is about one
    /// party: what a distribution keys on to withhold one holder's share
    /// instead of failing every holder's.
    fn ineligible_party(&self) -> Option<&Address> {
        match self {
            Self::NotCompliant { address }
            | Self::HolderFrozen { address, .. }
            | Self::MissingClaim { address, .. }
            | Self::JurisdictionNotAllowed { address, .. }
            | Self::AttestationExpired { address, .. }
            | Self::HolderCapReached { address, .. }
            | Self::HolderLimitExceeded { address, .. } => Some(address),
            _ => None,
        }
    }
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
    let state = holder_state(view, asset, party, current_height)?;

    // An issuer-frozen holder is out of circulation in both directions,
    // whatever its claims say.
    if state.frozen {
        return Err(RwaError::HolderFrozen {
            asset: asset.asset_ref.clone(),
            address: party.clone(),
        });
    }

    // A live claim proof stands in for the clear-text claims and
    // jurisdiction checks below; freeze and attestation age still apply.
    let proven = asset.private_claims
        && claim_proof_live(view, party, entry.as_ref(), &state, current_height)?;

    if proven {
        // `claim_proof_live` already required a live attestation.
    } else if !asset.required_claims.is_empty() {
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
    if let Some(allowed) = asset.allowed_jurisdictions.as_ref().filter(|_| !proven) {
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

/// How long an accepted `VerifyClaimProof` keeps clearing `check_party`
/// before the holder has to prove again — the periodic re-check compliance
/// expects, and the backstop for credential expiry the chain can't see.
pub const CLAIM_PROOF_TTL_SECS: u64 = 90 * 86_400;

/// Whether `state.claim_verified_at` still vouches for `party`: attestation
/// live (revocation or attestor deregistration closes the gate at once), not
/// re-granted since the proof (a new grant may carry narrower claims), and
/// within `CLAIM_PROOF_TTL_SECS`.
fn claim_proof_live<V: KvRead<Error = StorageError>>(
    view: &V,
    party: &Address,
    entry: Option<&AccountEntry>,
    state: &HolderState,
    current_height: u64,
) -> Result<bool, StorageError> {
    let Some(verified_at) = state.claim_verified_at else {
        return Ok(false);
    };
    if !entry
        .and_then(|e| e.attested_at)
        .is_some_and(|at| at <= verified_at)
        || !is_attested(view, party)?
    {
        return Ok(false);
    }
    let interval = view
        .get(&ChainParamsKey)?
        .unwrap_or_default()
        .block_interval_secs
        .max(1);
    Ok(current_height < verified_at.saturating_add(CLAIM_PROOF_TTL_SECS / interval))
}

/// Records an accepted claim proof (`circuit_identity::verify_claim_proof`)
/// for `holder` at `current_height`. Verification is the caller's job.
pub fn apply_record_claim_proof<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    holder: &Address,
    current_height: u64,
) -> Result<HolderStateUpdates, RwaError> {
    // Raw read, like `apply_set_holder_frozen`: don't drop an expired lock
    // as a side effect of an unrelated write.
    let mut state = view
        .get(&AssetHolderStateKey {
            asset: &asset.asset_ref,
            holder,
        })?
        .unwrap_or_default();
    state.claim_verified_at = Some(current_height);
    Ok(HolderStateUpdates(BTreeMap::from([(
        (asset.asset_ref.clone(), holder.clone()),
        state,
    )])))
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
    check_move(view, asset, sender, to, amount, current_height)?;

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

    let accounts = AccountUpdates(BTreeMap::from([(sender.clone(), sender_account)]));
    let assets = move_checked(view, asset, sender, to, amount, current_height)?;
    Ok((accounts, assets))
}

/// Every gate of a compliant transfer except the sender's nonce, then the
/// move. The nonce-less shape is what the corporate actions loop over — one
/// signed action, many compliant moves.
pub fn apply_compliant_move<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    from: &Address,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<AssetBalanceUpdates, RwaError> {
    check_move(view, asset, from, to, amount, current_height)?;
    move_checked(view, asset, from, to, amount, current_height)
}

/// The compliance half of a compliant transfer. First gate is the freeze,
/// ahead of compliance and balance: a freeze is meant to stop circulation
/// outright, so it must not be bypassable by a transfer that would have
/// failed a later check anyway for a different reason.
fn check_move<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &Asset,
    from: &Address,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<(), RwaError> {
    if asset.frozen {
        return Err(RwaError::AssetFrozen {
            asset: asset.asset_ref.clone(),
        });
    }
    check_party(view, asset, from, current_height)?;
    check_recipient(view, asset, to, amount, current_height)?;
    Ok(())
}

/// The balance half: partially frozen units stay put under a compliant
/// transfer (only a forced transfer or recovery moves them), then the move.
fn move_checked<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    from: &Address,
    to: &Address,
    amount: u128,
    current_height: u64,
) -> Result<AssetBalanceUpdates, RwaError> {
    let locked = holder_state(view, asset, from, current_height)?.frozen_amount;
    if locked > 0 {
        let balance = view
            .get(&AssetBalanceKey {
                asset: &asset.asset_ref,
                owner: from,
            })?
            .unwrap_or(0);
        let available = balance.saturating_sub(locked);
        if amount > available {
            return Err(RwaError::AmountLocked {
                asset: asset.asset_ref.clone(),
                sender: from.clone(),
                balance,
                locked,
                available,
                amount,
            });
        }
    }
    apply_forced_transfer(view, asset, from, to, amount)
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

/// Read-through overlay for one action that makes several balance moves:
/// staged writes shadow `base`, so the second move sees the first one's
/// debit instead of re-reading the pre-action balance. The same trick
/// `BlockView` plays across actions, one level down.
struct Staged<'a, V> {
    base: &'a V,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a, V: KvRead<Error = StorageError>> Staged<'a, V> {
    fn new(base: &'a V) -> Self {
        Self {
            base,
            entries: BTreeMap::new(),
        }
    }

    fn stage(&mut self, updates: &AssetBalanceUpdates) -> Result<(), StorageError> {
        self.entries.extend(updates.batch_entries()?);
        Ok(())
    }

    /// Everything staged, as one `AssetBalanceUpdates` — decoded back from
    /// the raw rows so the caller gets the same type every mover returns.
    fn into_updates(self) -> Result<AssetBalanceUpdates, StorageError> {
        let mut out = BTreeMap::new();
        for (key, value) in self.entries {
            let key = String::from_utf8(key).map_err(|_| StorageError::CorruptedMeta)?;
            let rest = key
                .strip_prefix("asset_balance:")
                .ok_or(StorageError::CorruptedMeta)?;
            let (asset, owner) = rest.rsplit_once(':').ok_or(StorageError::CorruptedMeta)?;
            let asset = AssetRef::parse(asset).map_err(|_| StorageError::CorruptedMeta)?;
            let owner = Address::parse(owner).map_err(|_| StorageError::CorruptedMeta)?;
            let (balance, _): (u128, _) =
                bincode::serde::decode_from_slice(&value, bincode::config::standard())?;
            out.insert((asset, owner), balance);
        }
        Ok(AssetBalanceUpdates(out))
    }
}

impl<V: KvRead<Error = StorageError>> KvRead for Staged<'_, V> {
    type Error = StorageError;

    fn get<K: KeySpec>(&self, key: &K) -> Result<Option<K::Value>, StorageError> {
        match self.entries.get(&key.encode()) {
            Some(bytes) => {
                let (value, _) =
                    bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
                Ok(Some(value))
            }
            None => self.base.get(key),
        }
    }
}

/// `SnapshotHolders`: records the cap table as of `current_height` on the
/// asset — every non-issuer address in the holders index with a positive
/// balance, read back through `view` so this block's earlier transfers
/// count. Replaces any previous snapshot.
// ponytail: the holders index (`meta:asset_holders`) is written at commit, so
// an address that first became a holder earlier in this same block is not
// listed yet. Take the snapshot one block after the last issuance if that
// matters. The index is unprovable state, so the adjudicator reports this
// action as unprovable rather than replaying it.
pub fn apply_snapshot<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    current_height: u64,
) -> Result<(), RwaError> {
    let mut holders = Vec::new();
    let mut total: u128 = 0;
    for holder in view
        .get(&AssetHoldersKey(&asset.asset_ref))?
        .unwrap_or_default()
    {
        if holder == asset.issuer {
            continue;
        }
        let balance = view
            .get(&AssetBalanceKey {
                asset: &asset.asset_ref,
                owner: &holder,
            })?
            .unwrap_or(0);
        if balance == 0 {
            continue;
        }
        total = total
            .checked_add(balance)
            .ok_or_else(|| RwaError::SupplyOverflow {
                asset: asset.asset_ref.clone(),
            })?;
        holders.push((holder, balance));
    }
    holders.sort();
    asset.snapshot = Some(CapTable {
        height: current_height,
        total,
        holders,
    });
    Ok(())
}

/// `holding * total / table.total`, the floor.
fn pro_rata(
    asset: &AssetRef,
    table: &CapTable,
    holding: u128,
    total: u128,
) -> Result<u128, RwaError> {
    holding
        .checked_mul(total)
        .map(|n| n / table.total)
        .ok_or_else(|| RwaError::ShareOverflow {
            asset: asset.clone(),
        })
}

/// `DistributeToHolders`: pays `total` of `payout` from `issuer` to every
/// holder in `table`, pro rata to their snapshot balance, as a sequence of
/// compliant moves of `payout`. A holder that fails `payout`'s own
/// compliance (frozen, stale KYC, over a limit) is withheld — its share stays
/// with the issuer to settle out of band — rather than failing everyone's.
/// Anything else (a frozen payout asset, the issuer short of balance or
/// locked) fails the whole action. Floor rounding leaves the dust with the
/// issuer.
pub fn apply_distribution<V: KvRead<Error = StorageError>>(
    view: &V,
    payout: &mut Asset,
    issuer: &Address,
    table: &CapTable,
    total: u128,
    current_height: u64,
) -> Result<AssetBalanceUpdates, RwaError> {
    let mut staged = Staged::new(view);
    for (holder, holding) in &table.holders {
        let share = pro_rata(&payout.asset_ref, table, *holding, total)?;
        if share == 0 {
            continue;
        }
        match apply_compliant_move(&staged, payout, issuer, holder, share, current_height) {
            Ok(updates) => staged.stage(&updates)?,
            Err(err) if err.ineligible_party() == Some(holder) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(staged.into_updates()?)
}

/// `RedeemHolders`: every snapshot balance of `asset` pulled back into the
/// issuer's treasury by forced transfer — no compliance gate, the units are
/// leaving circulation, and the asset may well be frozen for the record
/// period. The proceeds are a `DistributeToHolders` against the same
/// snapshot, kept separate so each action writes back one asset record. A
/// holder whose balance moved below its snapshot since the record date
/// fails the action: freeze the asset between snapshot and redemption. The
/// recovered units are the issuer's to burn.
pub fn apply_redemption<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    table: &CapTable,
) -> Result<AssetBalanceUpdates, RwaError> {
    let mut staged = Staged::new(view);
    let issuer = asset.issuer.clone();
    for (holder, holding) in &table.holders {
        staged.stage(&apply_forced_transfer(
            &staged, asset, holder, &issuer, *holding,
        )?)?;
    }
    asset.snapshot = None;
    Ok(staged.into_updates()?)
}

/// `SplitAsset`: every snapshot holding `b` becomes `b * numerator /
/// denominator`. Growth is minted straight to the holder (`apply_issue_to`,
/// so the cap, issuance lock and the holder's compliance all apply — a split
/// is uniform or it doesn't happen); shrinkage is forced back to the issuer's
/// treasury, which it may then burn. The treasury itself is not scaled.
pub fn apply_split<V: KvRead<Error = StorageError>>(
    view: &V,
    asset: &mut Asset,
    table: &CapTable,
    numerator: u128,
    denominator: u128,
    current_height: u64,
) -> Result<AssetBalanceUpdates, RwaError> {
    let mut staged = Staged::new(view);
    let issuer = asset.issuer.clone();
    for (holder, holding) in &table.holders {
        let scaled = holding
            .checked_mul(numerator)
            .map(|n: u128| n / denominator)
            .ok_or_else(|| RwaError::ShareOverflow {
                asset: asset.asset_ref.clone(),
            })?;
        let updates = if scaled > *holding {
            apply_issue_to(&staged, asset, holder, scaled - holding, current_height)?
        } else {
            apply_forced_transfer(&staged, asset, holder, &issuer, holding - scaled)?
        };
        staged.stage(&updates)?;
    }
    asset.snapshot = None;
    Ok(staged.into_updates()?)
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

    /// Writes balances and the cap-table index the way a block commit would.
    fn commit(db: &ArxiumDb, assets: &AssetBalanceUpdates) {
        let index = db.asset_index_updates(&[], assets).unwrap();
        db.write_batch(assets).unwrap();
        db.write_batch(&index).unwrap();
    }

    /// One dividend, one split, one redemption, all off one record-date
    /// snapshot: each is a loop of the existing movers over a staged view,
    /// so the second move must see the first one's debit.
    #[test]
    fn corporate_actions_compose_from_the_movers_over_one_snapshot() {
        let db = temp_db();
        let issuer = addr(1);
        let (a, b, c) = (addr(2), addr(3), addr(4));
        let mut bond = seeded_open_asset(&db, &issuer, 1_000);
        let mut usd = Asset::new("usd", addr(9), true);
        for who in [&issuer, &a, &b, &c] {
            attest(&db, who, &[], None);
        }
        // 60 / 30 / 10 of the bond in circulation; the issuer's treasury
        // holds 900 and is not a holder.
        let mut balances = AssetBalanceUpdates(BTreeMap::new());
        for (who, amount) in [(&a, 60), (&b, 30), (&c, 10)] {
            balances.0.extend(
                apply_forced_transfer(&db, &mut bond, &issuer, who, amount)
                    .unwrap()
                    .0,
            );
            db.write_batch(&balances).unwrap();
        }
        commit(&db, &balances);
        let (_, usd_treasury) = apply_issue(&db, &mut usd, &addr(9), 0, 10_000).unwrap();
        db.write_batch(&usd_treasury).unwrap();
        commit(
            &db,
            &apply_forced_transfer(&db, &mut usd, &addr(9), &issuer, 1_000).unwrap(),
        );

        apply_snapshot(&db, &mut bond, 7).unwrap();
        let table = bond.snapshot.clone().unwrap();
        assert_eq!(table.total, 100);
        assert_eq!(table.holders.len(), 3);

        // Dividend of 1,000 USD: 600 / 300 / 100 — but `c` is frozen for USD,
        // so its 100 is withheld and stays with the issuer.
        db.write_batch(&apply_set_holder_frozen(&db, &usd, &c, true).unwrap())
            .unwrap();
        let paid = apply_distribution(&db, &mut usd, &issuer, &table, 1_000, 8).unwrap();
        let bal = |who: &Address| paid.0.get(&(usd.asset_ref.clone(), who.clone())).copied();
        assert_eq!(bal(&a), Some(600));
        assert_eq!(bal(&b), Some(300));
        assert_eq!(bal(&c), None);
        assert_eq!(bal(&issuer), Some(100), "staged debits accumulate");
        // An issuer short of the payout is the whole action's failure, not a
        // withheld holder.
        let err = apply_distribution(&db, &mut usd, &issuer, &table, 5_000, 8).unwrap_err();
        assert!(
            matches!(err, RwaError::InsufficientBalance { .. }),
            "got: {err}"
        );

        // 3:2 split: 60/30/10 -> 90/45/15, minted, supply follows.
        let split = apply_split(&db, &mut bond, &table, 3, 2, 8).unwrap();
        let bal = |who: &Address| split.0.get(&(bond.asset_ref.clone(), who.clone())).copied();
        assert_eq!((bal(&a), bal(&b), bal(&c)), (Some(90), Some(45), Some(15)));
        assert_eq!(bond.total_supply, 1_050);
        assert!(bond.snapshot.is_none(), "a split invalidates the snapshot");

        // Redemption pulls every snapshot balance back to the treasury.
        let redeemed = apply_redemption(&db, &mut bond, &table).unwrap();
        let bal = |who: &Address| {
            redeemed
                .0
                .get(&(bond.asset_ref.clone(), who.clone()))
                .copied()
        };
        assert_eq!((bal(&a), bal(&b), bal(&c)), (Some(0), Some(0), Some(0)));
        assert_eq!(bal(&issuer), Some(1_000));
        assert_eq!(bond.holder_count, 0);
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
                claim_verified_at: None,
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
                claim_verified_at: None,
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

    /// D-17's "done when": a holder with no clear-text claims and
    /// `jurisdiction: None` clears a KYC + jurisdiction gate on a recorded
    /// claim proof — and only while the asset opts in, the attestation is
    /// live and unchanged since the proof, and the proof is within its TTL.
    #[test]
    fn a_live_claim_proof_stands_in_for_clear_claims_and_jurisdiction() {
        let db = temp_db();
        let (issuer, holder) = (addr(1), addr(2));
        let mut asset = Asset::new("bond", issuer.clone(), false);
        asset.required_claims = vec![ClaimTopic::Kyc];
        asset.allowed_jurisdictions = Some(vec!["CH".into()]);
        asset.private_claims = true;
        attest(&db, &issuer, &[ClaimTopic::Kyc], Some("CH"));
        let (accounts, assets) = apply_issue(&db, &mut asset, &issuer, 0, 100).unwrap();
        db.write_batch(&accounts).unwrap();
        db.write_batch(&assets).unwrap();
        let attested_at = |at: Option<u64>, hash: Option<&str>| {
            db.write_batch(&AccountUpdates(BTreeMap::from([(
                holder.clone(),
                AccountEntry {
                    identity_hash: hash.map(str::to_string),
                    attested_at: at,
                    ..Default::default()
                },
            )])))
            .unwrap();
        };
        let send = |asset: &mut Asset, height| {
            apply_compliant_transfer(&db, asset, &issuer, 1, &holder, 10, height)
        };

        attested_at(Some(5), Some("leaf"));
        assert!(matches!(
            send(&mut asset, 10),
            Err(RwaError::MissingClaim { .. })
        ));

        db.write_batch(&apply_record_claim_proof(&db, &asset, &holder, 10).unwrap())
            .unwrap();
        send(&mut asset, 10).expect("the proof clears claims and jurisdiction");

        let mut opted_out = asset.clone();
        opted_out.private_claims = false;
        assert!(matches!(
            send(&mut opted_out, 10),
            Err(RwaError::MissingClaim { .. })
        ));

        let ttl = CLAIM_PROOF_TTL_SECS / xc_primitives::ChainParams::default().block_interval_secs;
        send(&mut asset, 10 + ttl - 1).expect("still inside the TTL");
        assert!(matches!(
            send(&mut asset, 10 + ttl),
            Err(RwaError::MissingClaim { .. })
        ));

        // A re-grant after the proof may carry narrower claims: prove again.
        attested_at(Some(11), Some("leaf-v2"));
        assert!(matches!(
            send(&mut asset, 12),
            Err(RwaError::MissingClaim { .. })
        ));

        // Revocation closes the gate at once.
        attested_at(Some(5), None);
        assert!(matches!(
            send(&mut asset, 10),
            Err(RwaError::NotCompliant { .. })
        ));
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
