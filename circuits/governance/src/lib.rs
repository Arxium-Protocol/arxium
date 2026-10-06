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
    AccountKey, ChainParamsKey, DisputeOpenKey, KvRead, NextProposalIdKey, OpenDispute,
    ProposalKey, ValidatorSetKey, ValidatorStatusKey, VoteKey,
};
use xc_primitives::{
    Address, ChainParams, DisputeCause, DisputeResolution, GovernanceAction, Proposal,
    ProposalStatus, TOTAL_VOTING_POWER, ValidatorStatus, treasury_account,
    validator_set_effective_height,
};
use xc_storage::{
    AccountUpdates, AttestorDeregistration, AttestorRegistration, GovernanceUpdates, StorageError,
};

/// Evidence a validator checked before voting an attestor in: a content hash
/// and where to fetch it. Bounded so a proposal stays a small row.
const MAX_EVIDENCE_HASH_LEN: usize = 128;
const MAX_EVIDENCE_URI_LEN: usize = 512;

/// The attestor-registry writes an executed proposal produced, kept apart
/// from `GovernanceUpdates` so the block's effects log still reports them.
#[derive(Debug, Default)]
pub struct AttestorChange {
    pub registration: Option<AttestorRegistration>,
    pub deregistration: Option<AttestorDeregistration>,
}

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
    #[error("{0}")]
    Identity(#[from] circuit_identity::IdentityError),
    #[error("attestor evidence needs a hash of at most 128 and a uri of at most 512 characters")]
    InvalidEvidence,
    #[error("{0} is not an attestor")]
    UnknownAttestor(Address),
    #[error("balance {balance} cannot cover the {bond} IUM application bond")]
    CannotPayBond { bond: u128, balance: u128 },
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

/// Most release ids `ChainParams::canonical_builds` holds.
const MAX_CANONICAL_BUILDS: usize = 32;

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
            if p.canonical_builds.len() > MAX_CANONICAL_BUILDS
                || p.canonical_builds
                    .iter()
                    .any(|b| b.is_empty() || b.len() > xc_primitives::MAX_BUILD_ID_LEN)
            {
                return Err(GovernanceError::InvalidParams(
                    "canonical_builds: at most 32 non-empty ids of at most 64 bytes",
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
        GovernanceAction::AddAttestor {
            attestor,
            name,
            owners,
            threshold,
            evidence_hash,
            evidence_uri,
        } => {
            xc_primitives::validate_attestor_name(name)
                .map_err(circuit_identity::IdentityError::InvalidName)?;
            xc_primitives::validate_attestor_multisig(attestor, owners, *threshold)
                .map_err(circuit_identity::IdentityError::InvalidMultisig)?;
            if evidence_hash.is_empty()
                || evidence_hash.len() > MAX_EVIDENCE_HASH_LEN
                || evidence_uri.is_empty()
                || evidence_uri.len() > MAX_EVIDENCE_URI_LEN
            {
                return Err(GovernanceError::InvalidEvidence);
            }
        }
        GovernanceAction::RemoveAttestor { attestor }
        | GovernanceAction::UnblockAttestor { attestor } => {
            attestor
                .pubkey_bytes()
                .map_err(|_| GovernanceError::InvalidAddress(attestor.clone()))?;
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
    // A proposer-submitted proposal paid no bond; only an application does.
    open_proposal(view, proposer, action, description, current_height, 0)
}

/// What each attestor action needs from state before it is worth a vote, and
/// the removal block, which starts the moment the proposal exists.
fn open_proposal<V: KvRead<Error = StorageError>>(
    view: &V,
    proposer: &Address,
    action: GovernanceAction,
    description: &str,
    current_height: u64,
    bond: u128,
) -> Result<(u64, GovernanceUpdates), GovernanceError> {
    let params = chain_params(view)?;
    let mut voting_blocks = params.voting_period_blocks;
    let mut updates = GovernanceUpdates::default();
    match &action {
        GovernanceAction::AddAttestor {
            attestor,
            name,
            owners,
            threshold,
            ..
        } => {
            circuit_identity::apply_register_attestor(
                view,
                attestor,
                name,
                owners,
                *threshold,
                current_height,
            )?;
        }
        GovernanceAction::RemoveAttestor { attestor } => {
            updates.extend(circuit_identity::apply_open_removal(
                view,
                attestor,
                current_height,
            )?);
            voting_blocks = params.attestor_removal_voting_blocks;
        }
        GovernanceAction::UnblockAttestor { attestor } => {
            circuit_identity::require_attestor(view, attestor)
                .map_err(|_| GovernanceError::UnknownAttestor(attestor.clone()))?;
        }
        _ => {}
    }
    let id = view.get(&NextProposalIdKey)?.unwrap_or(0);
    let proposal = Proposal {
        id,
        proposer: proposer.clone(),
        action,
        description: description.to_string(),
        created_at: current_height,
        voting_ends_at: current_height.saturating_add(voting_blocks),
        yes_power: 0,
        no_power: 0,
        status: ProposalStatus::Open,
        bond,
    };
    updates.put(&ProposalKey(id), &proposal)?;
    updates.put(&NextProposalIdKey, &(id + 1))?;
    Ok((id, updates))
}

/// `ApplyAttestor`: `applicant` (the attestor's multisig address, which
/// signed the action and so controls it) pays the bond and opens the vote on
/// its own registration. It is not a validator and could not propose
/// otherwise; validators still decide, after checking the evidence off-chain.
#[allow(clippy::too_many_arguments)]
pub fn apply_attestor_application<V: KvRead<Error = StorageError>>(
    view: &V,
    applicant: &Address,
    name: &str,
    owners: &[Address],
    threshold: u8,
    evidence_hash: &str,
    evidence_uri: &str,
    current_height: u64,
) -> Result<(u64, GovernanceUpdates, AccountUpdates), GovernanceError> {
    let action = GovernanceAction::AddAttestor {
        attestor: applicant.clone(),
        name: name.to_string(),
        owners: owners.to_vec(),
        threshold,
        evidence_hash: evidence_hash.to_string(),
        evidence_uri: evidence_uri.to_string(),
    };
    validate_action(&action)?;
    // Refuse a name or address that cannot register before taking a bond.
    circuit_identity::apply_register_attestor(
        view,
        applicant,
        name,
        owners,
        threshold,
        current_height,
    )?;
    let bond = chain_params(view)?.attestor_apply_bond;
    let treasury = treasury_account();
    let mut payer = view.get(&AccountKey(applicant))?.unwrap_or_default();
    let rest = payer
        .balance
        .checked_sub(bond)
        .ok_or(GovernanceError::CannotPayBond {
            bond,
            balance: payer.balance,
        })?;
    payer.balance = rest;
    let mut treasury_entry = view.get(&AccountKey(&treasury))?.unwrap_or_default();
    treasury_entry.balance = treasury_entry.balance.saturating_add(bond);
    let accounts = AccountUpdates(BTreeMap::from([
        (applicant.clone(), payer),
        (treasury, treasury_entry),
    ]));
    let description = format!("Attestor application: {name}");
    let (id, updates) = open_proposal(view, applicant, action, &description, current_height, bond)?;
    Ok((id, updates, accounts))
}

/// Pays an application's bond back to its applicant out of the treasury, the
/// amount it paid, not today's `attestor_apply_bond`. The treasury is shared
/// and governance can spend it while a vote runs, so if it holds less than
/// the bond the applicant gets what is there: the attestor is registered
/// either way, since a vote that passed should not fail on the treasury.
fn refund_bond<V: KvRead<Error = StorageError>>(
    view: &V,
    proposal: &Proposal,
    accounts: &mut AccountUpdates,
) -> Result<(), GovernanceError> {
    if proposal.bond == 0 {
        return Ok(());
    }
    let treasury = treasury_account();
    let mut from = view.get(&AccountKey(&treasury))?.unwrap_or_default();
    let refund = proposal.bond.min(from.balance);
    from.balance -= refund;
    let mut to = view
        .get(&AccountKey(&proposal.proposer))?
        .unwrap_or_default();
    to.balance = to.balance.saturating_add(refund);
    accounts.0.insert(treasury, from);
    accounts.0.insert(proposal.proposer.clone(), to);
    Ok(())
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
) -> Result<
    (
        GovernanceUpdates,
        AccountUpdates,
        Option<OpenDispute>,
        AttestorChange,
    ),
    GovernanceError,
> {
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
    let mut attestors = AttestorChange::default();
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
            // State may have moved since submission (already registered,
            // name taken); that rejects the proposal rather than erroring.
            GovernanceAction::AddAttestor {
                attestor,
                name,
                owners,
                threshold,
                ..
            } => {
                if let Ok((registration, name_row)) = circuit_identity::apply_register_attestor(
                    view,
                    attestor,
                    name,
                    owners,
                    *threshold,
                    current_height,
                ) {
                    attestors.registration = Some(registration);
                    updates.extend(name_row);
                    proposal.status = ProposalStatus::Executed;
                    refund_bond(view, &proposal, &mut accounts)?;
                }
            }
            GovernanceAction::RemoveAttestor { attestor } => {
                if let Ok((deregistration, name_row)) =
                    circuit_identity::apply_deregister_attestor(view, attestor)
                {
                    attestors.deregistration = Some(deregistration);
                    updates.extend(name_row);
                    proposal.status = ProposalStatus::Executed;
                }
            }
            GovernanceAction::UnblockAttestor { attestor } => {
                if let Ok(unblocked) =
                    circuit_identity::apply_set_self_blocked(view, attestor, false)
                {
                    updates.extend(unblocked);
                    proposal.status = ProposalStatus::Executed;
                }
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
                // Raising the chain's `Bug` to `Attack` also falls through as
                // Rejected: a slash needs the provenance evidence behind it.
                if let Some(open) = view.get(&key)?
                    && !(open.cause == DisputeCause::Bug && *cause == DisputeCause::Attack)
                {
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
    // A removal vote that did not remove: whatever the reason, the block it
    // raised has to lift, or the attestor stays unable to grant for good.
    if let GovernanceAction::RemoveAttestor { attestor } = &proposal.action
        && proposal.status != ProposalStatus::Executed
    {
        updates.extend(circuit_identity::apply_close_failed_removal(
            view,
            attestor,
            current_height,
            chain_params(view)?.attestor_removal_cooldown_blocks,
        )?);
    }
    updates.put(&ProposalKey(id), &proposal)?;
    Ok((updates, accounts, slash, attestors))
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
            attestor_apply_bond: 100,
            attestor_removal_voting_blocks: 5,
            attestor_removal_cooldown_blocks: 20,
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
                    bond: 0,
                },
            )
            .unwrap();
        db.write_batch(&stored).unwrap();
        let (up, accounts, _, _) = apply_execute(&db, 0, 15).unwrap();
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

        let (up, accounts, _, _) = apply_execute(&db, 0, 15).unwrap();
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
        let (up, accounts, _, _) = apply_execute(&db, 1, 30).unwrap();
        assert!(accounts.0.is_empty());
        db.write_batch(&up).unwrap();
        let p: Proposal = KvRead::get(&db, &ProposalKey(1)).unwrap().unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
    }

    /// A 2-of-3 attestor address and its owners, distinct per `seed`.
    fn attestor_multisig(seed: u8) -> (Address, Vec<Address>) {
        let owners: Vec<Address> = (0..3).map(|i| addr(seed + i)).collect();
        let members: Vec<[u8; 32]> = (0..3).map(|i| [seed + i; 32]).collect();
        (
            xc_primitives::multisig_address(2, &members).unwrap(),
            owners,
        )
    }

    fn add_attestor(seed: u8, name: &str) -> GovernanceAction {
        let (attestor, owners) = attestor_multisig(seed);
        GovernanceAction::AddAttestor {
            attestor,
            name: name.into(),
            owners,
            threshold: 2,
            evidence_hash: "00".into(),
            evidence_uri: "https://example.com/evidence".into(),
        }
    }

    /// Writes a proposal's votes and executes it at `at`, applying every
    /// write the way the runtime does.
    fn vote_and_execute(
        db: &ArxiumDb,
        id: u64,
        votes: &[(u8, bool)],
        voted_at: u64,
        at: u64,
    ) -> Proposal {
        for (who, yes) in votes {
            db.write_batch(&apply_vote(db, &addr(*who), id, *yes, voted_at).unwrap())
                .unwrap();
        }
        let (up, accounts, _, attestors) = apply_execute(db, id, at).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&accounts).unwrap();
        if let Some(registration) = &attestors.registration {
            db.write_batch(registration).unwrap();
        }
        if let Some(deregistration) = &attestors.deregistration {
            db.write_batch(deregistration).unwrap();
        }
        KvRead::get(db, &ProposalKey(id)).unwrap().unwrap()
    }

    #[test]
    fn quorum_and_majority_are_both_required() {
        let db = db();
        let action = add_attestor(40, "Quorum Co");
        let (attestor, _) = attestor_multisig(40);
        // 30% + 10% yes is a majority of votes cast but under the 50% quorum.
        let (id, up) = apply_submit(&db, &addr(2), action.clone(), "", 0).unwrap();
        db.write_batch(&up).unwrap();
        let p = vote_and_execute(&db, id, &[(2, true), (3, true)], 1, 10);
        assert_eq!(p.status, ProposalStatus::Rejected);
        assert!(db.get_attestor_record(&attestor).unwrap().is_none());

        // 60% yes vs 40% no passes and registers the attestor.
        let (id, up) = apply_submit(&db, &addr(1), action, "", 10).unwrap();
        db.write_batch(&up).unwrap();
        let p = vote_and_execute(&db, id, &[(1, true), (2, false), (3, false)], 11, 20);
        assert_eq!(p.status, ProposalStatus::Executed);
        assert_eq!(
            db.get_attestor_record(&attestor).unwrap().unwrap().name,
            "Quorum Co"
        );
        // The listing skips the name-uniqueness rows beside the records.
        assert_eq!(db.list_attestors().unwrap().len(), 1);
    }

    /// The applicant is not a validator: it pays the bond and the proposal
    /// is opened on its behalf, then validators vote.
    #[test]
    fn an_application_pays_the_bond_opens_a_vote_and_registers_on_pass() {
        let db = db();
        let (applicant, owners) = attestor_multisig(50);
        let treasury = treasury_account();
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            applicant.clone(),
            AccountEntry {
                balance: 150,
                ..Default::default()
            },
        )])))
        .unwrap();
        let apply = |db: &ArxiumDb, who: &Address, name: &str, h| {
            apply_attestor_application(db, who, name, &owners, 2, "00", "https://e.example", h)
        };

        // A name no one may register, and a bond the applicant can't cover.
        assert!(matches!(
            apply(&db, &applicant, "Bad!", 1).unwrap_err(),
            GovernanceError::Identity(circuit_identity::IdentityError::InvalidName(_))
        ));
        let (poor, poor_owners) = attestor_multisig(55);
        assert!(matches!(
            apply_attestor_application(&db, &poor, "Poor Co", &poor_owners, 2, "00", "u", 1)
                .unwrap_err(),
            GovernanceError::CannotPayBond { .. }
        ));
        // Owners that don't derive the sender are refused.
        assert!(matches!(
            apply_attestor_application(&db, &addr(77), "Not Multi", &owners, 2, "00", "u", 1)
                .unwrap_err(),
            GovernanceError::Identity(circuit_identity::IdentityError::InvalidMultisig(_))
        ));

        let (id, up, accounts) = apply(&db, &applicant, "Regulated Bank", 1).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&accounts).unwrap();
        assert_eq!(db.get_account(&applicant).unwrap().unwrap().balance, 50);
        assert_eq!(db.get_account(&treasury).unwrap().unwrap().balance, 100);
        let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
        assert_eq!(p.proposer, applicant);
        assert_eq!(p.voting_ends_at, 11);

        let p = vote_and_execute(&db, id, &[(1, true)], 2, 11);
        assert_eq!(p.status, ProposalStatus::Executed);
        // The bond comes back when the vote passes.
        assert_eq!(db.get_account(&applicant).unwrap().unwrap().balance, 150);
        assert_eq!(db.get_account(&treasury).unwrap().unwrap().balance, 0);
        let record = db.get_attestor_record(&applicant).unwrap().unwrap();
        assert_eq!(
            (record.name.as_str(), record.threshold),
            ("Regulated Bank", 2)
        );
        // Registered: a lookalike name can't be proposed any more.
        let (other, other_owners) = attestor_multisig(60);
        assert!(matches!(
            apply_attestor_application(
                &db,
                &other,
                "Regu1ated bank",
                &other_owners,
                2,
                "00",
                "u",
                12
            )
            .unwrap_err(),
            GovernanceError::Identity(circuit_identity::IdentityError::NameTaken(_))
        ));
    }

    /// A funded applicant that has applied; returns its address, the
    /// proposal id and the account's balance after paying the bond (100).
    fn applied(db: &ArxiumDb, seed: u8, name: &str) -> (Address, u64) {
        let (applicant, owners) = attestor_multisig(seed);
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            applicant.clone(),
            AccountEntry {
                balance: 150,
                ..Default::default()
            },
        )])))
        .unwrap();
        let (id, up, accounts) =
            apply_attestor_application(db, &applicant, name, &owners, 2, "00", "u", 1).unwrap();
        db.write_batch(&up).unwrap();
        db.write_batch(&accounts).unwrap();
        assert_eq!(db.get_account(&applicant).unwrap().unwrap().balance, 50);
        (applicant, id)
    }

    fn balance(db: &ArxiumDb, who: &Address) -> u128 {
        db.get_account(who).unwrap().map_or(0, |a| a.balance)
    }

    #[test]
    fn a_failed_application_keeps_the_bond() {
        let db = db();
        let (applicant, id) = applied(&db, 100, "Doomed Co");
        // No votes: the window closes and the proposal is rejected.
        let p = vote_and_execute(&db, id, &[], 0, 11);
        assert_eq!(p.status, ProposalStatus::Rejected);
        assert!(db.get_attestor_record(&applicant).unwrap().is_none());
        assert_eq!(balance(&db, &applicant), 50);
        assert_eq!(balance(&db, &treasury_account()), 100);
        // A NO majority is the same.
        let (applicant, id) = applied(&db, 110, "Refused Co");
        let p = vote_and_execute(&db, id, &[(1, false)], 2, 11);
        assert_eq!(p.status, ProposalStatus::Rejected);
        assert_eq!(balance(&db, &applicant), 50);
    }

    /// Governance can change the bond while a vote runs; the refund is what
    /// the applicant paid.
    #[test]
    fn the_refund_is_the_amount_paid_not_the_current_param() {
        let db = db();
        let (applicant, id) = applied(&db, 120, "Steady Co");
        db.write_batch(&ChainParamsRow(ChainParams {
            voting_period_blocks: 10,
            attestor_apply_bond: 999,
            ..Default::default()
        }))
        .unwrap();
        let p = vote_and_execute(&db, id, &[(1, true)], 2, 11);
        assert_eq!(p.status, ProposalStatus::Executed);
        assert_eq!(balance(&db, &applicant), 150);
        assert_eq!(balance(&db, &treasury_account()), 0);
    }

    /// A validator-submitted add paid nothing, so it refunds nothing and
    /// cannot draw on the treasury.
    #[test]
    fn a_validator_submitted_add_refunds_nothing() {
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
        let (attestor, _) = attestor_multisig(130);
        let (id, up) = apply_submit(&db, &addr(1), add_attestor(130, "Direct Co"), "", 0).unwrap();
        db.write_batch(&up).unwrap();
        let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
        assert_eq!(p.bond, 0);
        db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
            .unwrap();
        let (_, accounts, _, _) = apply_execute(&db, id, 10).unwrap();
        assert!(accounts.0.is_empty(), "no account is written: {accounts:?}");
        assert_eq!(balance(&db, &treasury), 100);
        assert_eq!(balance(&db, &attestor), 0);
    }

    /// The treasury is shared: if it was spent down while the vote ran, the
    /// applicant gets what is there and the attestor still registers.
    #[test]
    fn a_short_treasury_refunds_what_is_left_and_still_registers() {
        let db = db();
        let (applicant, id) = applied(&db, 140, "Late Co");
        db.write_batch(&AccountUpdates(BTreeMap::from([(
            treasury_account(),
            AccountEntry {
                balance: 30,
                ..Default::default()
            },
        )])))
        .unwrap();
        let p = vote_and_execute(&db, id, &[(1, true)], 2, 11);
        assert_eq!(p.status, ProposalStatus::Executed);
        assert!(db.get_attestor_record(&applicant).unwrap().is_some());
        assert_eq!(balance(&db, &applicant), 80);
        assert_eq!(balance(&db, &treasury_account()), 0);
    }

    fn registered(db: &ArxiumDb, seed: u8, name: &str) -> Address {
        let (attestor, _) = attestor_multisig(seed);
        let (id, up) = apply_submit(db, &addr(1), add_attestor(seed, name), "", 0).unwrap();
        db.write_batch(&up).unwrap();
        vote_and_execute(db, id, &[(1, true)], 0, 10);
        attestor
    }

    fn can_grant(db: &ArxiumDb, attestor: &Address, height: u64) -> bool {
        circuit_identity::apply_grant_attestation(db, attestor, &addr(5), "h", &[], None, height)
            .is_ok()
    }

    #[test]
    fn a_removal_vote_blocks_grants_until_it_closes_and_a_failed_one_cools_down() {
        let db = db();
        let attestor = registered(&db, 70, "Removal Co");
        assert!(can_grant(&db, &attestor, 11));
        let remove = GovernanceAction::RemoveAttestor {
            attestor: attestor.clone(),
        };

        // Only validators propose removals.
        assert!(matches!(
            apply_submit(&db, &addr(9), remove.clone(), "", 20).unwrap_err(),
            GovernanceError::NotValidator(_)
        ));
        let (id, up) = apply_submit(&db, &addr(1), remove.clone(), "", 20).unwrap();
        db.write_batch(&up).unwrap();
        let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
        assert_eq!(p.voting_ends_at, 25, "removals use the shorter window");
        assert!(
            !can_grant(&db, &attestor, 21),
            "blocked while the vote runs"
        );
        // One at a time.
        assert!(matches!(
            apply_submit(&db, &addr(2), remove.clone(), "", 21).unwrap_err(),
            GovernanceError::Identity(circuit_identity::IdentityError::RemovalPending(_))
        ));

        // Nobody votes, the window passes: the proposal fails, the block lifts.
        let p = vote_and_execute(&db, id, &[], 0, 25);
        assert_eq!(p.status, ProposalStatus::Rejected);
        assert!(can_grant(&db, &attestor, 26));
        // Cooldown: barred until height 25 + 20.
        assert!(matches!(
            apply_submit(&db, &addr(1), remove.clone(), "", 44).unwrap_err(),
            GovernanceError::Identity(circuit_identity::IdentityError::RemovalCooldown { .. })
        ));
        // Something it granted before the second vote.
        let alice = addr(5);
        db.write_batch(
            &circuit_identity::apply_grant_attestation(&db, &attestor, &alice, "h", &[], None, 26)
                .unwrap(),
        )
        .unwrap();
        let (id, up) = apply_submit(&db, &addr(1), remove, "", 45).unwrap();
        db.write_batch(&up).unwrap();
        // This one passes: the attestor is gone, what it granted stops counting.

        let p = vote_and_execute(&db, id, &[(1, true)], 46, 50);
        assert_eq!(p.status, ProposalStatus::Executed);
        assert!(db.get_attestor_record(&attestor).unwrap().is_none());
        assert!(!circuit_identity::is_attested(&db, &alice).unwrap());
        // The name is free again.
        let (id, up) = apply_submit(&db, &addr(1), add_attestor(80, "REMOVAL co"), "", 51).unwrap();
        db.write_batch(&up).unwrap();
        assert_eq!(
            vote_and_execute(&db, id, &[(1, true)], 52, 61).status,
            ProposalStatus::Executed
        );
    }

    #[test]
    fn only_a_vote_lifts_a_self_block() {
        let db = db();
        let attestor = registered(&db, 90, "Careful Co");
        db.write_batch(&circuit_identity::apply_set_self_blocked(&db, &attestor, true).unwrap())
            .unwrap();
        assert!(!can_grant(&db, &attestor, 11));
        let unblock = GovernanceAction::UnblockAttestor {
            attestor: attestor.clone(),
        };
        // Unknown attestors are refused before anyone votes.
        assert!(matches!(
            apply_submit(
                &db,
                &addr(1),
                GovernanceAction::UnblockAttestor { attestor: addr(77) },
                "",
                11
            )
            .unwrap_err(),
            GovernanceError::UnknownAttestor(_)
        ));
        let (id, up) = apply_submit(&db, &addr(1), unblock, "", 11).unwrap();
        db.write_batch(&up).unwrap();
        assert!(!can_grant(&db, &attestor, 12), "still blocked while voting");
        let p = vote_and_execute(&db, id, &[(1, true)], 12, 21);
        assert_eq!(p.status, ProposalStatus::Executed);
        assert!(can_grant(&db, &attestor, 22));
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
        let (up, _, _, _) = apply_execute(&db, id, 10).unwrap();
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
                    bond: 0,
                },
            )
            .unwrap();
        db.write_batch(&stored).unwrap();
        let (up, _, _, _) = apply_execute(&db, 0, 10).unwrap();
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
            cause: None,
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
            let (up, accounts, _, _) = apply_execute(&db, id, 10).unwrap();
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
            let (up, _, _, _) = apply_execute(&db, id, 10).unwrap();
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
            cause: Some(DisputeCause::Attack),
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
            let (up, accounts, slash, _) = apply_execute(&db, id, 10).unwrap();
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
            cause: Some(DisputeCause::Attack),
            challenger: Some(challenger.clone()),
        })
        .unwrap();
        let ((_, slash), status) = execute(2, resolve(DisputeCause::Attack, 0, vec![]));
        assert_eq!(status, ProposalStatus::Executed);
        assert_eq!(
            slash,
            Some(OpenDispute {
                culprit,
                challenger,
                cause: DisputeCause::Attack,
            })
        );
    }

    /// The chain's classification caps governance: a dispute it called a bug
    /// can't be voted into an attack (no slash without provenance), and an
    /// attack can be voted down to a bug.
    #[test]
    fn governance_can_lower_the_chains_classification_but_not_raise_it() {
        let db = db();
        let (culprit, challenger) = (addr(3), addr(4));
        let header = [9u8; 32];
        let open = |cause| {
            db.write_batch(&xc_storage::EvidenceMarker {
                height: 3,
                proposer: culprit.clone(),
                disputed: Some(header),
                cause: Some(cause),
                challenger: Some(challenger.clone()),
            })
            .unwrap();
        };
        let resolve = |cause| GovernanceAction::ResolveDispute {
            height: 3,
            header,
            resolution: DisputeResolution::Accept,
            corrections: vec![],
            cause,
            bounty: 0,
        };
        let mut next = 0u64;
        let mut execute = |action| {
            let id = next;
            next += 1;
            let (got, up) = apply_submit(&db, &addr(1), action, "", 0).unwrap();
            assert_eq!(got, id);
            db.write_batch(&up).unwrap();
            db.write_batch(&apply_vote(&db, &addr(1), id, true, 1).unwrap())
                .unwrap();
            let (up, accounts, slash, _) = apply_execute(&db, id, 10).unwrap();
            db.write_batch(&up).unwrap();
            db.write_batch(&accounts).unwrap();
            let p: Proposal = KvRead::get(&db, &ProposalKey(id)).unwrap().unwrap();
            (slash, p.status)
        };

        open(DisputeCause::Bug);
        let (slash, status) = execute(resolve(DisputeCause::Attack));
        assert_eq!((slash, status), (None, ProposalStatus::Rejected));
        assert_eq!(db.lowest_open_dispute().unwrap(), Some(3));

        open(DisputeCause::Attack);
        let (slash, status) = execute(resolve(DisputeCause::Bug));
        assert_eq!((slash, status), (None, ProposalStatus::Executed));
        assert_eq!(db.lowest_open_dispute().unwrap(), None);
    }
}
