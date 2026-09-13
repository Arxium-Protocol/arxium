// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The validator-set state machine end to end, through the real
//! `on_block_sealed` hook against a real db: joins wait for the boundary,
//! leaves linger until it, jails release on schedule, tombstones never do,
//! and a set that would be too small keeps the previous one.

use std::collections::BTreeMap;

use xc_circuit::ValidatorStatusKey;
use xc_primitives::{AccountEntry, Address, ChainParams, ValidatorStatus, VotingPower, boundary_of};
use xc_runtime_api::ChainRuntime;
use xc_storage::{AccountUpdates, ArxiumDb, BlockView, ChainParamsRow, StakeUpdates, ValidatorSetSnapshot, ValidatorStatusUpdates};

use crate::CoreChainRuntime;
use crate::staking::MIN_VALIDATOR_STAKE;
use crate::test_support::temp_db;

const EPOCH: u64 = 10;

fn addr(n: u8) -> Address {
    Address::from_pubkey_bytes(&[n; 32]).unwrap()
}

fn params() -> ChainParams {
    ChainParams { epoch_length: EPOCH, validator_attestation_required: false, min_validator_set: 2, max_validator_set: 100 }
}

/// Genesis-shaped db: `members` active with equal power, each self-staked
/// `stake`, params seeded.
fn chain(members: &[u8], stake: u128) -> ArxiumDb {
    let db = temp_db();
    let addrs: Vec<Address> = members.iter().map(|n| addr(*n)).collect();
    db.write_batch(&ValidatorSetSnapshot::equal_power(0, &addrs)).unwrap();
    let mut statuses = ValidatorStatusUpdates::default();
    for a in &addrs {
        statuses.0.insert(a.clone(), Some(ValidatorStatus::Active));
        stake_to(&db, a, stake);
    }
    db.write_batch(&statuses).unwrap();
    db.write_batch(&ChainParamsRow(params())).unwrap();
    db
}

fn stake_to(db: &ArxiumDb, validator: &Address, amount: u128) {
    let mut updates = StakeUpdates::default();
    updates.allocations.insert(
        (validator.clone(), validator.clone()),
        Some(xc_primitives::StakeAllocation {
            master: validator.clone(),
            validator: validator.clone(),
            active_amount: amount,
            unbonding: None,
            created_at: 0,
            updated_at: 0,
        }),
    );
    updates.validator_index.insert(validator.clone(), vec![validator.clone()]);
    db.write_batch(&updates).unwrap();
}

fn set_status(db: &ArxiumDb, validator: &Address, status: Option<ValidatorStatus>) {
    let mut updates = ValidatorStatusUpdates::default();
    updates.0.insert(validator.clone(), status);
    db.write_batch(&updates).unwrap();
}

/// Seals `height` as if `proposer` produced it on schedule, persisting what
/// the hook returns exactly as the executor would.
fn seal(db: &ArxiumDb, height: u64) -> Option<BTreeMap<Address, VotingPower>> {
    let validators = db.validator_addresses_at(height).unwrap();
    let proposer = xc_primitives::expected_proposer(&validators, height).unwrap();
    let view = BlockView::new(db);
    let updates = CoreChainRuntime::on_block_sealed(&view, &proposer, 0, &validators, height).unwrap();
    db.write_batch(&updates.accounts).unwrap();
    db.write_batch(&updates.stakes).unwrap();
    db.write_batch(&updates.validator_statuses).unwrap();
    if let Some(set) = &updates.validator_set {
        db.write_batch(&ValidatorSetSnapshot { effective_height: height + 1, validators: set.clone() }).unwrap();
    }
    updates.validator_set
}

fn status(db: &ArxiumDb, validator: &Address) -> Option<ValidatorStatus> {
    xc_circuit::KvRead::get(db, &ValidatorStatusKey(validator)).unwrap()
}

#[test]
fn nothing_happens_off_a_boundary_and_a_pending_join_waits_for_it() {
    let db = chain(&[1, 2], MIN_VALIDATOR_STAKE);
    // 3 joins mid-epoch: `Pending`, staked at the floor.
    stake_to(&db, &addr(3), MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(3), Some(ValidatorStatus::Pending));

    for h in 1..boundary_of(0, EPOCH) {
        assert!(seal(&db, h).is_none(), "height {h} is not a boundary");
        assert_eq!(db.validator_addresses_at(h + 1).unwrap().len(), 2);
    }
    let set = seal(&db, boundary_of(0, EPOCH)).expect("boundary writes a set");
    assert_eq!(set.len(), 3);
    assert_eq!(set.values().map(|p| p.0).sum::<u32>(), 10_000);
    assert_eq!(db.validator_addresses_at(boundary_of(0, EPOCH)).unwrap().len(), 2, "the boundary block itself is on the old set");
    assert_eq!(db.validator_addresses_at(boundary_of(0, EPOCH) + 1).unwrap().len(), 3);
    assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Active));
}

#[test]
fn power_follows_stake_at_the_boundary() {
    let db = chain(&[1, 2], MIN_VALIDATOR_STAKE);
    // Eighteen more join so the 10% cap is live, one of them a whale.
    for n in 3..=20 {
        stake_to(&db, &addr(n), if n == 20 { 50 * MIN_VALIDATOR_STAKE } else { MIN_VALIDATOR_STAKE });
        set_status(&db, &addr(n), Some(ValidatorStatus::Pending));
    }
    let set = seal(&db, boundary_of(0, EPOCH)).unwrap();
    assert_eq!(set.len(), 20);
    assert_eq!(set[&addr(20)], VotingPower(1_000), "capped at 10%");
    assert!(set.values().all(|p| p.0 <= 1_000));
    assert_eq!(set.values().map(|p| p.0).sum::<u32>(), 10_000);
}

#[test]
fn a_leaving_validator_votes_until_the_boundary_then_drops_and_its_row_is_cleared() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(3), Some(ValidatorStatus::Leaving { from_epoch: 1 }));
    assert_eq!(db.validator_addresses_at(5).unwrap().len(), 3, "still a member mid-epoch");
    let set = seal(&db, boundary_of(0, EPOCH)).unwrap();
    assert_eq!(set.len(), 2);
    assert!(!set.contains_key(&addr(3)));
    assert_eq!(status(&db, &addr(3)), None, "the row served its purpose");
}

#[test]
fn falling_below_the_floor_ejects_at_the_boundary_not_before() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    stake_to(&db, &addr(3), MIN_VALIDATOR_STAKE - 1);
    assert_eq!(db.validator_addresses_at(4).unwrap().len(), 3);
    let set = seal(&db, boundary_of(0, EPOCH)).unwrap();
    assert!(!set.contains_key(&addr(3)));
    assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Pending), "back to waiting, not gone");
}

#[test]
fn jail_excludes_until_its_epoch_then_readmits() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(3), Some(ValidatorStatus::Jailed { until_epoch: 2 }));
    // Boundary of epoch 0 → set for epoch 1: still jailed.
    let set = seal(&db, boundary_of(0, EPOCH)).unwrap();
    assert!(!set.contains_key(&addr(3)));
    assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Jailed { until_epoch: 2 }));
    // Boundary of epoch 1 → set for epoch 2: released.
    let set = seal(&db, boundary_of(1, EPOCH)).unwrap();
    assert!(set.contains_key(&addr(3)));
    assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Active));
}

#[test]
fn a_missed_slot_slashes_and_jails_the_primary() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    let height = 4;
    let validators = db.validator_addresses_at(height).unwrap();
    let primary = xc_primitives::expected_proposer(&validators, height).unwrap();
    let backup = validators.iter().find(|v| **v != primary).unwrap().clone();
    let view = BlockView::new(&db);
    let updates = CoreChainRuntime::on_block_sealed(&view, &backup, 0, &validators, height).unwrap();
    assert_eq!(
        updates.validator_statuses.0.get(&primary),
        Some(&Some(ValidatorStatus::Jailed { until_epoch: 2 })),
        "epoch 0 + 2"
    );
    let slashed = updates.stakes.allocations[&(primary.clone(), primary.clone())].as_ref().unwrap();
    assert!(slashed.active_amount < MIN_VALIDATOR_STAKE);
    assert!(updates.validator_set.is_none(), "not a boundary");
}

#[test]
fn a_tombstoned_validator_is_never_readmitted_whatever_it_stakes() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(3), Some(ValidatorStatus::Tombstoned));
    stake_to(&db, &addr(3), 1_000 * MIN_VALIDATOR_STAKE);
    for epoch in 0..3 {
        let set = seal(&db, boundary_of(epoch, EPOCH)).unwrap();
        assert!(!set.contains_key(&addr(3)));
        assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Tombstoned));
    }
    // And the admission gate says the same thing before any stake moves.
    let view = BlockView::new(&db);
    let err = crate::staking::check_join_admission(&view, &addr(3)).unwrap_err();
    assert!(err.to_string().contains("tombstoned"), "{err}");
}

#[test]
fn too_few_eligible_keeps_the_previous_set() {
    let db = chain(&[1, 2, 3], MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(2), Some(ValidatorStatus::Tombstoned));
    set_status(&db, &addr(3), Some(ValidatorStatus::Jailed { until_epoch: 9 }));
    // Only 1 qualifies, minimum is 2: no new snapshot, old set stands.
    assert!(seal(&db, boundary_of(0, EPOCH)).is_none());
    assert_eq!(db.validator_addresses_at(boundary_of(0, EPOCH) + 1).unwrap().len(), 3);
}

#[test]
fn the_attestation_gate_is_a_chain_param() {
    let db = chain(&[1, 2], MIN_VALIDATOR_STAKE);
    stake_to(&db, &addr(3), MIN_VALIDATOR_STAKE);
    set_status(&db, &addr(3), Some(ValidatorStatus::Pending));
    // Off (devnet): unattested 3 joins.
    let view = BlockView::new(&db);
    assert!(crate::staking::check_join_admission(&view, &addr(3)).is_ok());
    assert!(seal(&db, boundary_of(0, EPOCH)).unwrap().contains_key(&addr(3)));

    // On (mainnet): rejected at admission, and filtered at the boundary.
    // 1 and 2 are attested by a *registered* attestor so the set stays
    // above the minimum and the filter — not the too-few fallback — is what
    // drops 3; 3 has an identity record, but from an attestor that is no
    // longer in the registry, which must not count.
    db.write_batch(&ChainParamsRow(ChainParams { validator_attestation_required: true, ..params() })).unwrap();
    let attestor = addr(9);
    let gone = addr(8);
    db.write_batch(&xc_storage::AttestorRegistration {
        attestor: attestor.clone(),
        record: xc_primitives::AttestorRecord { name: "kyc-co".into(), registered_at: 0 },
    })
    .unwrap();
    let attested = AccountEntry { identity_hash: Some("kyc".into()), attested_by: Some(attestor), ..Default::default() };
    let stale = AccountEntry { identity_hash: Some("kyc".into()), attested_by: Some(gone), ..Default::default() };
    db.write_batch(&AccountUpdates(BTreeMap::from([(addr(1), attested.clone()), (addr(2), attested), (addr(3), stale)])))
        .unwrap();
    let view = BlockView::new(&db);
    let err = crate::staking::check_join_admission(&view, &addr(3)).unwrap_err();
    assert!(err.to_string().contains("attestation"), "{err}");
    let set = seal(&db, boundary_of(1, EPOCH)).unwrap();
    assert_eq!(set.len(), 2);
    assert!(!set.contains_key(&addr(3)));
    assert_eq!(status(&db, &addr(3)), Some(ValidatorStatus::Pending));
}

#[test]
fn the_set_is_cut_at_max_validator_set_by_stake() {
    let db = chain(&[1, 2], MIN_VALIDATOR_STAKE);
    db.write_batch(&ChainParamsRow(ChainParams { max_validator_set: 3, ..params() })).unwrap();
    for n in 3..=6 {
        stake_to(&db, &addr(n), MIN_VALIDATOR_STAKE * n as u128);
        set_status(&db, &addr(n), Some(ValidatorStatus::Pending));
    }
    let set = seal(&db, boundary_of(0, EPOCH)).unwrap();
    assert_eq!(set.len(), 3);
    assert!(set.contains_key(&addr(6)) && set.contains_key(&addr(5)) && set.contains_key(&addr(4)));
    assert_eq!(status(&db, &addr(1)), Some(ValidatorStatus::Pending), "cut from the set, back to waiting");
}
