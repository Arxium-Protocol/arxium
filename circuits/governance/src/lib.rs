// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! On-chain governance, the Hybrid-phase shape of whitepaper §10 cut to what
//! a single regulated chain needs: the active validator set votes, weighted
//! by the `VotingPower` it already carries for finality, on one of three
//! actions — a `chain_params` change, an admin-role rotation, a treasury
//! spend. No delegation, lock multipliers, deposits or veto council; add
//! them when someone outside the validator set needs a say.
//!
//! Execution is an explicit action (`apply_execute`) rather than a
//! boundary-hook scan: it costs a fee, lands in a block as a replayable step,
//! and so is attributable and provable like any other state change.
//!
//! Same shape as every circuit: plain arguments, read-only view, typed
//! errors, returns updates without writing them.

use std::collections::BTreeMap;

use thiserror::Error;
use xc_circuit::{
    AccountKey, AdminKey, AdminRole, ChainParamsKey, DisputeOpenKey, KvRead, NextProposalIdKey,
    OpenDispute, ProposalKey, ValidatorSetKey, ValidatorStatusKey, VoteKey,
};
use xc_primitives::{
    Address, ChainParams, DisputeCause, DisputeResolution, GovernanceAction, Proposal,
    ProposalStatus, TOTAL_VOTING_POWER, ValidatorStatus, treasury_account,
    validator_set_effective_height,
};
use xc_storage::{AccountUpdates, GovernanceUpdates, StorageError};

#[derive(Error, Debug)]
pub enum GovernanceError {
    #[error("storage error {0}")]
    Storage(#[from] StorageError),
    #[error("{0} is not in the active validator set")]
    NotValidator(Address),
    #[error("proposal {0} does not exist")]
    UnknownProposal(u64),
    #[error("proposal {0} is not open")]
    NotOpen(u64),
    #[error("voting on proposal {id} closed at height {ends_at}")]
    VotingClosed { id: u64, ends_at: u64 },
    #[error("voting on proposal {id} is open until height {ends_at}")]
    VotingStillOpen { id: u64, ends_at: u64 },
    #[error("{voter} already voted on proposal {id}")]
    AlreadyVoted { id: u64, voter: Address },
    #[error("unknown admin role {0:?}")]
    UnknownRole(String),
    #[error("treasury spend of {amount} exceeds the treasury balance of {balance}")]
    TreasuryInsufficient { amount: u128, balance: u128 },
    #[error("treasury spend amount must be positive")]
    ZeroSpend,
    #[error("{0} is not a valid address")]
    InvalidAddress(Address),
    #[error("a forked resolution carries no corrections")]
    ForkedWithCorrections,
    #[error("an attack verdict carries no corrections and no bounty")]
    AttackWithPayouts,
    #[error("chain params rejected: {0}")]
    InvalidParams(&'static str),
}

fn chain_params<V: KvRead<Error = StorageError>>(view: &V) -> Result<ChainParams, StorageError> {
    Ok(view.get(&ChainParamsKey)?.unwrap_or_default())
}

/// `who`'s power in the set in force at `current_height` — one provable key.
fn voting_power<V: KvRead<Error = StorageError>>(
    view: &V,
    who: &Address,
    current_height: u64,
) -> Result<u32, GovernanceError> {
    let epoch_length = chain_params(view)?.epoch_length;
    let set = view
        .get(&ValidatorSetKey(validator_set_effective_height(
            current_height,
            epoch_length,
        )))?
        .unwrap_or_default();
    set.get(who)
        .map(|p| p.0)
        .ok_or_else(|| GovernanceError::NotValidator(who.clone()))
}

fn proposal<V: KvRead<Error = StorageError>>(
    view: &V,
    id: u64,
) -> Result<Proposal, GovernanceError> {
    view.get(&ProposalKey(id))?
        .ok_or(GovernanceError::UnknownProposal(id))
}

/// Epochs are `height / epoch_length` from genesis, and the set in force is
/// read from one exact key (`validator_set_effective_height`). A new length
/// moves that key to a height with no row (empty set, nobody can vote) or
/// back onto an old row (a stale set votes), and re-numbers every stored
/// epoch index (`Leaving { from_epoch }`, jail `until_epoch`).
/// ponytail: fixed for the chain's life; retuning needs an epoch grid
/// anchored at the height the change takes effect.
fn changes_epoch_length<V: KvRead<Error = StorageError>>(
    view: &V,
    proposed: &ChainParams,
) -> Result<bool, StorageError> {
    Ok(proposed.epoch_length != chain_params(view)?.epoch_length)
}

/// The cheap sanity checks on a proposed action, run at submission so a
/// proposal that could never execute isn't voted on for a week. State-
/// dependent checks (treasury balance) wait for execution.
fn validate_action(action: &GovernanceAction) -> Result<(), GovernanceError> {
    match action {
        GovernanceAction::SetChainParams(p) => {
            if p.block_interval_secs == 0 {
                return Err(GovernanceError::InvalidParams(
                    "block_interval_secs must be positive",
                ));
            }
            if p.epoch_length == 0 {
                return Err(GovernanceError::InvalidParams(
                    "epoch_length must be positive",
                ));
            }
            if p.min_validator_set == 0 || p.min_validator_set > p.max_validator_set {
                return Err(GovernanceError::InvalidParams(
                    "need 0 < min_validator_set <= max_validator_set",
                ));
            }
            if p.max_block_weight == 0 {
                return Err(GovernanceError::InvalidParams(
                    "max_block_weight must be positive",
                ));
            }
            if p.voting_period_blocks == 0 {
                return Err(GovernanceError::InvalidParams(
                    "voting_period_blocks must be positive",
                ));
            }
            if p.proposal_quorum_bps > TOTAL_VOTING_POWER {
                return Err(GovernanceError::InvalidParams(
                    "proposal_quorum_bps is over 10_000",
                ));
            }
            if p.action_fee == 0 {
                return Err(GovernanceError::InvalidParams(
                    "action_fee must be positive",
                ));
            }
            if p.min_validator_stake == 0 {
                return Err(GovernanceError::InvalidParams(
                    "min_validator_stake must be positive",
                ));
            }
            if p.equivocation_slash_bps > 10_000 || p.downtime_slash_bps > 10_000 {
                return Err(GovernanceError::InvalidParams("a slash rate is over 100%"));
            }
            if p.fee_proposer_bps.saturating_add(p.fee_treasury_bps) > 10_000 {
                return Err(GovernanceError::InvalidParams(
                    "fee_proposer_bps + fee_treasury_bps is over 100%",
                ));
            }
            // Zero would make execution faults unslashable; at or past
            // unbonding, a culprit could leave before its fault is due.
            if p.challenge_window_blocks == 0 || p.challenge_window_blocks >= p.unbonding_blocks {
                return Err(GovernanceError::InvalidParams(
                    "challenge_window_blocks must be positive and below unbonding_blocks",
                ));
            }
            if p.challenger_reward_bps > 1_000 {
                return Err(GovernanceError::InvalidParams(
                    "challenger_reward_bps is over 10%",
                ));
            }
        }
        GovernanceAction::SetAdmin { role, address } => {
            AdminRole::parse(role).ok_or_else(|| GovernanceError::UnknownRole(role.clone()))?;
            address
                .pubkey_bytes()
                .map_err(|_| GovernanceError::InvalidAddress(address.clone()))?;
        }
        GovernanceAction::TreasurySpend { to, amount } => {
            if *amount == 0 {
                return Err(GovernanceError::ZeroSpend);
            }
            if *to == treasury_account() {
                return Err(GovernanceError::InvalidAddress(to.clone()));
            }
            to.pubkey_bytes()
                .map_err(|_| GovernanceError::InvalidAddress(to.clone()))?;
        }
        GovernanceAction::ReinstateValidator { validator } => {
            validator
                .pubkey_bytes()
                .map_err(|_| GovernanceError::InvalidAddress(validator.clone()))?;
        }
        GovernanceAction::ResolveDispute {
            resolution,
            corrections,
            cause,
            bounty,
            ..
        } => {
            if *resolution == DisputeResolution::Forked && !corrections.is_empty() {
                return Err(GovernanceError::ForkedWithCorrections);
            }
            // The slash is computed from the same view as these writes, so
            // the two must not touch the same account rows.
            if *cause == DisputeCause::Attack && (!corrections.is_empty() || *bounty > 0) {
                return Err(GovernanceError::AttackWithPayouts);
            }
            for (who, _) in corrections {
                who.pubkey_bytes()
                    .map_err(|_| GovernanceError::InvalidAddress(who.clone()))?;
            }
        }
    }
    Ok(())
}

/// Opens a proposal. `proposer` must be an active validator — the same set
/// that votes. Returns the id it was assigned.
pub fn apply_submit<V: KvRead<Error = StorageError>>(
    view: &V,
    proposer: &Address,
    action: GovernanceAction,
    description: &str,
    current_height: u64,
) -> Result<(u64, GovernanceUpdates), GovernanceError> {
    voting_power(view, proposer, current_height)?;
    validate_action(&action)?;
    if let GovernanceAction::SetChainParams(p) = &action
        && changes_epoch_length(view, p)?
    {
        return Err(GovernanceError::InvalidParams(
            "epoch_length can't be changed by governance",
        ));
    }
    let id = view.get(&NextProposalIdKey)?.unwrap_or(0);
    let proposal = Proposal {
        id,
        proposer: proposer.clone(),
        action,
        description: description.to_string(),
        created_at: current_height,
        voting_ends_at: current_height.saturating_add(chain_params(view)?.voting_period_blocks),
        yes_power: 0,
        no_power: 0,
        status: ProposalStatus::Open,
    };
    let mut updates = GovernanceUpdates::default();
    updates.put(&ProposalKey(id), &proposal)?;
    updates.put(&NextProposalIdKey, &(id + 1))?;
    Ok((id, updates))
}

/// One vote per validator per proposal, weighted by its power in the set in
/// force *now* — a validator that joined after submission still votes, one
/// that left cannot.
pub fn apply_vote<V: KvRead<Error = StorageError>>(
    view: &V,
    voter: &Address,
    id: u64,
    approve: bool,
    current_height: u64,
) -> Result<GovernanceUpdates, GovernanceError> {
    let power = voting_power(view, voter, current_height)?;
    let mut proposal = proposal(view, id)?;
    if proposal.status != ProposalStatus::Open {
        return Err(GovernanceError::NotOpen(id));
    }
    if current_height >= proposal.voting_ends_at {
        return Err(GovernanceError::VotingClosed {
            id,
            ends_at: proposal.voting_ends_at,
        });
    }
    let vote_key = VoteKey {
        proposal: id,
        voter,
    };
    if view.get(&vote_key)?.is_some() {
        return Err(GovernanceError::AlreadyVoted {
            id,
            voter: voter.clone(),
        });
    }
    if approve {
        proposal.yes_power = proposal.yes_power.saturating_add(power);
    } else {
        proposal.no_power = proposal.no_power.saturating_add(power);
    }
    let mut updates = GovernanceUpdates::default();
    updates.put(&ProposalKey(id), &proposal)?;
    updates.put(&vote_key, &approve)?;
    Ok(updates)
}

/// Closes a proposal whose window has ended: applies its action if it
/// passed (yes > no and yes ≥ quorum), records `Rejected` otherwise. Anyone
/// may call it — the outcome is fixed by the tally, not by who closes it.
/// An action that can't apply at execution time (treasury short) rejects
/// the proposal rather than leaving it open forever.
pub fn apply_execute<V: KvRead<Error = StorageError>>(
    view: &V,
    id: u64,
    current_height: u64,
) -> Result<(GovernanceUpdates, AccountUpdates, Option<OpenDispute>), GovernanceError> {
    let mut proposal = proposal(view, id)?;
    if proposal.status != ProposalStatus::Open {
        return Err(GovernanceError::NotOpen(id));
    }
    if current_height < proposal.voting_ends_at {
        return Err(GovernanceError::VotingStillOpen {
            id,
            ends_at: proposal.voting_ends_at,
        });
    }
    let quorum = chain_params(view)?.proposal_quorum_bps;
    let passed = proposal.yes_power > proposal.no_power && proposal.yes_power >= quorum;

    let mut updates = GovernanceUpdates::default();
    let mut accounts = AccountUpdates(BTreeMap::new());
    // An executed `Attack` verdict: the caller slashes (the circuit has no
    // staking logic) and must do so in the same block.
    let mut slash = None;
    proposal.status = ProposalStatus::Rejected;
    if passed {
        match &proposal.action {
            // Refused at submission too; kept for proposals stored before
            // that check. Falls through as Rejected.
            GovernanceAction::SetChainParams(params) if changes_epoch_length(view, params)? => {}
            GovernanceAction::SetChainParams(params) => {
                updates.put(&ChainParamsKey, params)?;
                proposal.status = ProposalStatus::Executed;
            }
            GovernanceAction::SetAdmin { role, address } => {
                // Validated at submission; an unknown role here is a bug.
                let role = AdminRole::parse(role)
                    .ok_or_else(|| GovernanceError::UnknownRole(role.clone()))?;
                updates.put(&AdminKey(role), address)?;
                proposal.status = ProposalStatus::Executed;
            }
            GovernanceAction::TreasurySpend { to, amount } => {
                let treasury = treasury_account();
                let mut from = view.get(&AccountKey(&treasury))?.unwrap_or_default();
                // Refused at submission too; kept here for proposals stored
                // before that check. Debiting and crediting the same row
                // would write the credit over the debit and mint `amount`.
                if to == &treasury {
                    // Falls through as Rejected.
                } else if let Some(rest) = from.balance.checked_sub(*amount) {
                    from.balance = rest;
                    let mut dest = view.get(&AccountKey(to))?.unwrap_or_default();
                    dest.balance = dest.balance.saturating_add(*amount);
                    accounts.0.insert(treasury, from);
                    accounts.0.insert(to.clone(), dest);
                    proposal.status = ProposalStatus::Executed;
                }
                // Short treasury: falls through as Rejected — see doc.
            }
            GovernanceAction::ResolveDispute {
                height,
                header,
                corrections,
                cause,
                bounty,
                ..
            } => {
                let key = DisputeOpenKey {
                    height: *height,
                    header: *header,
                };
                // Nothing open (already resolved) falls through as Rejected.
                if let Some(open) = view.get(&key)? {
                    let treasury = treasury_account();
                    let mut paid = true;
                    if *bounty > 0 {
                        let mut from = view.get(&AccountKey(&treasury))?.unwrap_or_default();
                        // Short treasury (or a bounty to the treasury itself)
                        // rejects, like `TreasurySpend`.
                        if let (Some(rest), true) = (
                            from.balance.checked_sub(*bounty),
                            open.challenger != treasury,
                        ) {
                            from.balance = rest;
                            let mut dest =
                                view.get(&AccountKey(&open.challenger))?.unwrap_or_default();
                            dest.balance = dest.balance.saturating_add(*bounty);
                            accounts.0.insert(treasury.clone(), from);
                            accounts.0.insert(open.challenger.clone(), dest);
                        } else {
                            paid = false;
                        }
                    }
                    if paid {
                        for (who, balance) in corrections {
                            // A correction wins over the bounty on the same row.
                            let mut entry = match accounts.0.get(who) {
                                Some(entry) => entry.clone(),
                                None => view.get(&AccountKey(who))?.unwrap_or_default(),
                            };
                            entry.balance = *balance;
                            accounts.0.insert(who.clone(), entry);
                        }
                        updates.delete(&key);
                        if *cause == DisputeCause::Attack {
                            slash = Some(open);
                        }
                        proposal.status = ProposalStatus::Executed;
                    } else {
                        accounts.0.clear();
                    }
                }
            }
            GovernanceAction::ReinstateValidator { validator } => {
                // Not tombstoned (never was, or already reinstated) falls
                // through as Rejected.
                if view.get(&ValidatorStatusKey(validator))? == Some(ValidatorStatus::Tombstoned) {
                    updates.delete(&ValidatorStatusKey(validator));
                    proposal.status = ProposalStatus::Executed;
                }
            }
        }
    }
    updates.put(&ProposalKey(id), &proposal)?;
    Ok((updates, accounts, slash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::{AccountEntry, VotingPower};
    use xc_storage::{ArxiumDb, ChainParamsRow, ValidatorSetSnapshot};

    fn addr(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    /// Three validators at 60/30/10 % from genesis, 10-block voting window.
    fn db() -> ArxiumDb {
        // The counter keeps parallel tests apart: macOS clocks tick in µs,
        // so two tests can read the same nanos.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
        let path = std::env::temp_dir().join(format!("arxium-test-governance-{nanos}"));
        let db = ArxiumDb::open(&path).unwrap();
        let set = BTreeMap::from([
            (addr(1), VotingPower(6_000)),
            (addr(2), VotingPower(3_000)),
            (addr(3), VotingPower(1_000)),
        ]);
        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: set,
        })
        .unwrap();
        db.write_batch(&ChainParamsRow(ChainParams {
            voting_period_blocks: 10,
            ..Default::default()
        }))
        .unwrap();
        db
    }

    /// Debit and credit hit the same row, so the credit used to overwrite
    /// the debit and mint `amount` into the treasury.
    #[test]
    fn a_treasury_spend_to_the_treasury_is_refused() {
        let db = db();
        let spend = GovernanceAction::TreasurySpend {
            to: treasury_account(),
            amount: 60,
        };
        assert!(matches!(
            apply_submit(&db, &addr(1), spend.clone(), "loop", 5).unwrap_err(),
            GovernanceError::InvalidAddress(_)
        ));
        // A proposal stored before the submission check still can't mint.
        let treasury = treasury_account();
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            treasury.clone(),
            AccountEntry {
                balance: 100,
                ..Default::default()
            },
        )])))
        .unwrap();
        let mut stored = GovernanceUpdates::default();
        stored
            .put(
                &ProposalKey(0),
                &Proposal {
                    id: 0,
                    proposer: addr(1),
                    action: spend,
                    description: "loop".into(),
                    created_at: 5,
                    voting_ends_at: 15,
                    yes_power: 9_000,
                    no_power: 0,
                    status: ProposalStatus::Open,
                },
            )
            .unwrap();
        db.write_batch(&stored).unwrap();
        let (up, accounts, _) = apply_execute(&db, 0, 15).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&accounts).unwrap();
        assert_eq!(db.get_account(&treasury).unwrap().unwrap().balance, 100);
        let p: Proposal = KvRead::get(&db, &ProposalKey(0)).unwrap().unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
    }

    #[test]
    fn a_passing_treasury_spend_moves_funds_and_a_failing_one_rejects() {
        let db = db();
        let treasury = treasury_account();
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            treasury.clone(),
            AccountEntry {
                balance: 100,
                ..Default::default()
            },
        )])))
        .unwrap();

        let spend = GovernanceAction::TreasurySpend {
            to: addr(9),
            amount: 60,
        };
        let (id, up) = apply_submit(&db, &addr(1), spend.clone(), "grant", 5).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(id, 0);
        assert!(matches!(
            apply_submit(&db, &addr(7), spend.clone(), "", 5).unwrap_err(),
            GovernanceError::NotValidator(_)
        ));

        // 60% yes clears the 50% quorum; the 30% no doesn't outweigh it.
        db.write_batch(&apply_vote(&db, &addr(1), 0, true, 6).unwrap())
            .unwrap();
        db.write_batch(&apply_vote(&db, &addr(2), 0, false, 6).unwrap())
            .unwrap();
        assert!(matches!(
            apply_vote(&db, &addr(1), 0, true, 7).unwrap_err(),
            GovernanceError::AlreadyVoted { .. }
        ));
        assert!(matches!(
            apply_execute(&db, 0, 14).unwrap_err(),
            GovernanceError::VotingStillOpen { .. }
        ));
        assert!(matches!(
            apply_vote(&db, &addr(3), 0, true, 15).unwrap_err(),
            GovernanceError::VotingClosed { .. }
        ));

        let (up, accounts, _) = apply_execute(&db, 0, 15).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&accounts).unwrap();
        assert_eq!(db.get_account(&treasury).unwrap().unwrap().balance, 40);
        assert_eq!(db.get_account(&addr(9)).unwrap().unwrap().balance, 60);
        let p: Proposal = KvRead::get(&db, &ProposalKey(0)).unwrap().unwrap();
        assert_eq!(
            (p.status, p.yes_power, p.no_power),
            (ProposalStatus::Executed, 6_000, 3_000)
        );
        assert!(matches!(
            apply_execute(&db, 0, 16).unwrap_err(),
            GovernanceError::NotOpen(0)
        ));

        // Second spend passes the vote but the treasury only has 40 left.
        let (id, up) = apply_submit(&db, &addr(1), spend, "again", 20).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(id, 1);
        db.write_batch(&apply_vote(&db, &addr(1), 1, true, 21).unwrap())
            .unwrap();
        let (up, accounts, _) = apply_execute(&db, 1, 30).unwrap();
        assert!(accounts.0.is_empty());
        db.write_batch(&up).unwrap();
        let p: Proposal = KvRead::get(&db, &ProposalKey(1)).unwrap().unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
    }

    #[test]
    fn quorum_and_majority_are_both_required() {
        let db = db();
        let action = GovernanceAction::SetAdmin {
            role: "freeze".into(),
            address: addr(9),
        };
        // 30% + 10% yes is a majority of votes cast but under the 50% quorum.
        let (id, up) = apply_submit(&db, &addr(2), action.clone(), "", 0).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&apply_vote(&db, &addr(2), id, true, 1).unwrap())
            .unwrap();
        db.write_batch(&apply_vote(&db, &addr(3), id, true, 1).unwrap())
            .unwrap();
        let (up, _, _) = apply_execute(&db, id, 10).unwrap();
        db.write_batch(&up).unwrap();
        let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
        assert!(
            KvRead::get(&db, &AdminKey(AdminRole::Freeze))
                .unwrap()
                .is_none()
        );

        // 60% yes vs 40% no passes and rotates the role.
        let (id, up) = apply_submit(&db, &addr(1), action, "", 10).unwrap();
        db.write_batch(&up).unwrap();
        for (who, yes) in [(1, true), (2, false), (3, false)] {
            db.write_batch(&apply_vote(&db, &addr(who), id, yes, 11).unwrap())
                .unwrap();
        }
        let (up, _, _) = apply_execute(&db, id, 20).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(
            KvRead::get(&db, &AdminKey(AdminRole::Freeze)).unwrap(),
            Some(addr(9))
        );
    }

    #[test]
    fn chain_params_proposals_are_validated_at_submission_and_applied_on_pass() {
        let db = db();
        for bad in [
            ChainParams {
                block_interval_secs: 0,
                ..Default::default()
            },
            ChainParams {
                epoch_length: 0,
                ..Default::default()
            },
            ChainParams {
                action_fee: 0,
                ..Default::default()
            },
            ChainParams {
                equivocation_slash_bps: 10_001,
                ..Default::default()
            },
            ChainParams {
                fee_proposer_bps: 6_000,
                fee_treasury_bps: 5_000,
                ..Default::default()
            },
            ChainParams {
                challenge_window_blocks: 0,
                ..Default::default()
            },
            ChainParams {
                challenge_window_blocks: ChainParams::default().unbonding_blocks,
                ..Default::default()
            },
            ChainParams {
                challenger_reward_bps: 1_001,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                apply_submit(&db, &addr(1), GovernanceAction::SetChainParams(bad), "", 0)
                    .unwrap_err(),
                GovernanceError::InvalidParams(_)
            ));
        }
        let new_params = ChainParams {
            reward_per_block: 1,
            voting_period_blocks: 10,
            ..Default::default()
        };
        let (id, up) = apply_submit(
            &db,
            &addr(1),
            GovernanceAction::SetChainParams(new_params.clone()),
            "",
            0,
        )
        .unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
            .unwrap();
        let (up, _, _) = apply_execute(&db, id, 10).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(chain_params(&db).unwrap(), new_params);
    }

    #[test]
    fn epoch_length_changes_are_refused_and_stored_ones_rejected() {
        let db = db();
        let before = chain_params(&db).unwrap();
        let longer = ChainParams {
            epoch_length: before.epoch_length * 2,
            ..before.clone()
        };
        assert!(matches!(
            apply_submit(
                &db,
                &addr(1),
                GovernanceAction::SetChainParams(longer.clone()),
                "",
                0
            )
            .unwrap_err(),
            GovernanceError::InvalidParams(_)
        ));

        // A passing proposal stored before submission checked this.
        let mut stored = GovernanceUpdates::default();
        stored
            .put(
                &ProposalKey(0),
                &Proposal {
                    id: 0,
                    proposer: addr(1),
                    action: GovernanceAction::SetChainParams(longer),
                    description: String::new(),
                    created_at: 0,
                    voting_ends_at: 10,
                    yes_power: TOTAL_VOTING_POWER,
                    no_power: 0,
                    status: ProposalStatus::Open,
                },
            )
            .unwrap();
        db.write_batch(&stored).unwrap();
        let (up, _, _) = apply_execute(&db, 0, 10).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(proposal(&db, 0).unwrap().status, ProposalStatus::Rejected);
        assert_eq!(chain_params(&db).unwrap(), before);
    }

    /// A passed `ResolveDispute` deletes the open marker (settlement
    /// resumes), applies its balance corrections, and can't run twice.
    #[test]
    fn resolving_a_dispute_resumes_settlement_and_applies_corrections() {
        let db = db();
        let header = [7u8; 32];
        db.write_batch(&xc_storage::EvidenceMarker {
            height: 3,
            proposer: addr(3),
            disputed: Some(header),
            challenger: Some(addr(2)),
        })
        .unwrap();
        assert_eq!(db.lowest_open_dispute().unwrap(), Some(3));

        let resolve = |resolution, corrections| GovernanceAction::ResolveDispute {
            height: 3,
            header,
            resolution,
            corrections,
            cause: DisputeCause::Bug,
            bounty: 0,
        };
        assert!(matches!(
            apply_submit(
                &db,
                &addr(1),
                resolve(DisputeResolution::Forked, vec![(addr(2), 5)]),
                "",
                0
            )
            .unwrap_err(),
            GovernanceError::ForkedWithCorrections
        ));

        let run = |id_hint: u64| {
            let (id, up) = apply_submit(
                &db,
                &addr(1),
                resolve(DisputeResolution::Accept, vec![(addr(2), 42)]),
                "",
                0,
            )
            .unwrap();
            assert_eq!(id, id_hint);
            db.write_batch(&up).unwrap();
            db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
                .unwrap();
            let (up, accounts, _) = apply_execute(&db, id, 10).unwrap();
            db.write_batch(&up).unwrap();
            db.write_batch(&accounts).unwrap();
            let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
            p.status
        };
        assert_eq!(run(0), ProposalStatus::Executed);
        assert_eq!(db.lowest_open_dispute().unwrap(), None);
        assert_eq!(db.get_account(&addr(2)).unwrap().unwrap().balance, 42);
        // Nothing left to resolve: the second proposal rejects.
        assert_eq!(run(1), ProposalStatus::Rejected);
    }

    /// A passed `ReinstateValidator` lifts a tombstone (the row is gone, so
    /// admission no longer refuses it) and rejects when there is none.
    #[test]
    fn reinstating_lifts_a_tombstone_once() {
        let db = db();
        db.write_batch(&xc_storage::ValidatorStatusUpdates(
            [(addr(3), Some(ValidatorStatus::Tombstoned))].into(),
        ))
        .unwrap();
        let run = |id: u64| {
            let (got, up) = apply_submit(
                &db,
                &addr(1),
                GovernanceAction::ReinstateValidator { validator: addr(3) },
                "",
                0,
            )
            .unwrap();
            assert_eq!(got, id);
            db.write_batch(&up).unwrap();
            db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
                .unwrap();
            let (up, _, _) = apply_execute(&db, id, 10).unwrap();
            db.write_batch(&up).unwrap();
            let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
            p.status
        };
        assert_eq!(run(0), ProposalStatus::Executed);
        assert_eq!(
            KvRead::get(&db, &ValidatorStatusKey(&addr(3))).unwrap(),
            None
        );
        assert_eq!(run(1), ProposalStatus::Rejected);
    }

    /// Verdicts: a bug pays the challenger from the treasury (and rejects on a
    /// short treasury, leaving the dispute open); an attack asks the caller to
    /// slash the culprit and carries no payouts.
    #[test]
    fn verdicts_pay_a_bounty_or_request_a_slash() {
        let db = db();
        let header = [7u8; 32];
        let (culprit, challenger) = (addr(3), addr(2));
        db.write_batch(&xc_storage::EvidenceMarker {
            height: 3,
            proposer: culprit.clone(),
            disputed: Some(header),
            challenger: Some(challenger.clone()),
        })
        .unwrap();
        db.write_batch(&AccountUpdates(
            [(
                treasury_account(),
                xc_primitives::AccountEntry {
                    balance: 100,
                    ..Default::default()
                },
            )]
            .into(),
        ))
        .unwrap();
        let resolve = |cause, bounty, corrections| GovernanceAction::ResolveDispute {
            height: 3,
            header,
            resolution: DisputeResolution::Accept,
            corrections,
            cause,
            bounty,
        };
        let execute = |id: u64, action| {
            let (got, up) = apply_submit(&db, &addr(1), action, "", 0).unwrap();
            assert_eq!(got, id);
            db.write_batch(&up).unwrap();
            db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
                .unwrap();
            let (up, accounts, slash) = apply_execute(&db, id, 10).unwrap();
            db.write_batch(&up).unwrap();
            db.write_batch(&accounts).unwrap();
            let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
            ((accounts.0.len(), slash), p.status)
        };

        assert!(matches!(
            apply_submit(
                &db,
                &addr(1),
                resolve(DisputeCause::Attack, 5, vec![]),
                "",
                0
            )
            .unwrap_err(),
            GovernanceError::AttackWithPayouts
        ));
        // Treasury holds 100: a bounty of 500 rejects and the dispute stays open.
        let ((written, slash), status) = execute(0, resolve(DisputeCause::Bug, 500, vec![]));
        assert_eq!(
            (status, slash, written),
            (ProposalStatus::Rejected, None, 0)
        );
        assert_eq!(db.lowest_open_dispute().unwrap(), Some(3));
        // Affordable bounty: challenger paid, no slash, dispute closed.
        let ((_, slash), status) = execute(1, resolve(DisputeCause::Bug, 60, vec![]));
        assert_eq!((status, slash), (ProposalStatus::Executed, None));
        assert_eq!(db.get_account(&challenger).unwrap().unwrap().balance, 60);
        assert_eq!(
            db.get_account(&treasury_account())
                .unwrap()
                .unwrap()
                .balance,
            40
        );
        assert_eq!(db.lowest_open_dispute().unwrap(), None);

        // Attack: reopen and expect the culprit and challenger back.
        db.write_batch(&xc_storage::EvidenceMarker {
            height: 3,
            proposer: culprit.clone(),
            disputed: Some(header),
            challenger: Some(challenger.clone()),
        })
        .unwrap();
        let ((_, slash), status) = execute(2, resolve(DisputeCause::Attack, 0, vec![]));
        assert_eq!(status, ProposalStatus::Executed);
        assert_eq!(
            slash,
            Some(OpenDispute {
                culprit,
                challenger
            })
        );
    }
}
