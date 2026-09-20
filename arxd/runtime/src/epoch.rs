// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The epoch-boundary hook: at the last block of every epoch, pick next
//! epoch's validator set from stake and status, weigh it, and hand it back
//! to the executor as the `ValidatorSetSnapshot` effective at the next
//! height. This is the *only* writer of the set — a join, leave, jail or
//! tombstone changes a status row and waits for the boundary.

use std::collections::BTreeMap;

use tracing::warn;
use xc_circuit::{ChainParamsKey, KvRead, StakeByValidatorKey, StakeKey, ValidatorStatusKey};
use xc_executor::BlockUpdates;
use xc_primitives::{
    Address, ValidatorStatus, VotingPower, assign_voting_power, epoch_of, is_boundary,
};
use xc_storage::{BlockView, StorageError};

/// Runs inside `on_block_sealed`. Off a boundary it does nothing. On one it
/// always returns a set (and the status rows it changed): the next one, or,
/// when fewer than `min_validator_set` qualify, the previous one re-written
/// with a warning — never a set that cannot reach quorum, and never a
/// boundary without a row (see `xc_circuit::ValidatorSetKey`).
pub(crate) fn boundary_hook(view: &BlockView<'_>, height: u64) -> anyhow::Result<BlockUpdates> {
    let params = view.get(&ChainParamsKey)?.unwrap_or_default();
    let mut updates = BlockUpdates::default();
    if !is_boundary(height, params.epoch_length) {
        return Ok(updates);
    }
    let next_epoch = epoch_of(height, params.epoch_length) + 1;

    // Candidates come from a db scan (the overlay can't iterate), each row
    // then read back through the view so a status written earlier in this
    // very block is honoured.
    let mut statuses: BTreeMap<Address, ValidatorStatus> = BTreeMap::new();
    for (address, scanned) in view.db().all_validator_statuses()? {
        let status = view.get(&ValidatorStatusKey(&address))?.unwrap_or(scanned);
        statuses.insert(address, status);
    }

    let mut eligible: Vec<(Address, u128)> = Vec::new();
    for (address, status) in &statuses {
        if !status.eligible_for(next_epoch) {
            continue;
        }
        let Some(stake) = total_stake(view, address)? else {
            continue;
        };
        if stake < params.min_validator_stake {
            continue;
        }
        if params.validator_attestation_required && !circuit_rwa_asset::is_attested(view, address)?
        {
            continue;
        }
        eligible.push((address.clone(), stake));
    }
    // Top `max_validator_set` by stake; ties broken by address so every
    // node cuts the list at the same place.
    eligible.sort_by(|(a, sa), (b, sb)| sb.cmp(sa).then_with(|| a.cmp(b)));
    eligible.truncate(params.max_validator_set.max(1));

    if eligible.len() < params.min_validator_set {
        warn!(
            height,
            next_epoch,
            eligible = eligible.len(),
            minimum = params.min_validator_set,
            "epoch boundary: too few eligible validators, keeping the previous set"
        );
        // Kept, but still written at this boundary's height: the row's
        // location is what makes the set provable as one key
        // (`ValidatorSetKey(validator_set_effective_height(H))`), so every
        // boundary writes one whether or not the membership moved.
        updates.validator_set = Some(view.db().get_validator_set_at(height)?);
        return Ok(updates);
    }

    let stakes: BTreeMap<Address, u128> = eligible.into_iter().collect();
    let set: BTreeMap<Address, VotingPower> = assign_voting_power(&stakes);
    for (address, status) in &statuses {
        let next = if set.contains_key(address) {
            Some(ValidatorStatus::Active)
        } else {
            match status {
                // Announced leaving and now out: the row has served its purpose.
                ValidatorStatus::Leaving { from_epoch } if *from_epoch <= next_epoch => None,
                // Was in, fell out (below the floor, or past the top-100 cut).
                ValidatorStatus::Active => Some(ValidatorStatus::Pending),
                _ => continue,
            }
        };
        if next.as_ref() != Some(status) {
            updates.validator_statuses.0.insert(address.clone(), next);
        }
    }
    updates.validator_set = Some(set);
    Ok(updates)
}

/// Sum of every active allocation staked to `validator` — one master today
/// (`circuit_staking`'s single-master invariant), but summed so a relaxed
/// invariant later doesn't silently under-count. `None` when nothing is
/// staked at all.
fn total_stake<V: KvRead<Error = StorageError>>(
    view: &V,
    validator: &Address,
) -> Result<Option<u128>, StorageError> {
    let masters = view
        .get(&StakeByValidatorKey(validator))?
        .unwrap_or_default();
    if masters.is_empty() {
        return Ok(None);
    }
    let mut total = 0u128;
    for master in &masters {
        if let Some(allocation) = view.get(&StakeKey { master, validator })? {
            total = total.saturating_add(allocation.active_amount);
        }
    }
    Ok(Some(total))
}
