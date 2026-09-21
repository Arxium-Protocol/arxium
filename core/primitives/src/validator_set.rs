// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The stake-weighted validator set: voting power, epochs, and validator
//! status. Every function here is pure — same input, same output, no I/O —
//! because all of it is consensus-critical arithmetic that every node must
//! reproduce bit-for-bit from the same stake snapshot.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Address;

/// One validator's share of consensus influence, in units of
/// `TOTAL_VOTING_POWER`. A newtype so a raw stake amount (u128 IUM) can
/// never be mistaken for a power (u32 basis points of the whole).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct VotingPower(pub u32);

/// Every active set's powers sum to exactly this.
pub const TOTAL_VOTING_POWER: u32 = 10_000;

/// Signed power at or above this finalizes: strictly more than two thirds of
/// `TOTAL_VOTING_POWER` (6,666.67 rounds up).
pub const QUORUM_POWER: u32 = 6_667;

/// Whether `signers`' combined power in `set` reaches `QUORUM_POWER`. A
/// signer not in `set` contributes nothing; membership is still the caller's
/// check, this just never lets an outsider count.
pub fn quorum_reached<'a>(
    set: &BTreeMap<Address, VotingPower>,
    signers: impl IntoIterator<Item = &'a Address>,
) -> bool {
    signed_power(set, signers) >= QUORUM_POWER
}

/// Sum of `signers`' power in `set`, ignoring duplicates and non-members.
pub fn signed_power<'a>(
    set: &BTreeMap<Address, VotingPower>,
    signers: impl IntoIterator<Item = &'a Address>,
) -> u32 {
    let mut seen = std::collections::BTreeSet::new();
    signers
        .into_iter()
        .filter(|s| seen.insert(*s))
        .filter_map(|s| set.get(s))
        .map(|p| p.0)
        .sum()
}

/// Epoch `height` falls in. Epoch 0 is heights `0..epoch_length`.
pub fn epoch_of(height: u64, epoch_length: u64) -> u64 {
    height / epoch_length.max(1)
}

/// The last height of `epoch` — where the boundary hook runs and writes the
/// set that takes effect at `boundary_of(epoch) + 1`.
pub fn boundary_of(epoch: u64, epoch_length: u64) -> u64 {
    (epoch + 1) * epoch_length.max(1) - 1
}

/// The height whose `validator_set:` row is in force at `height`: genesis
/// (`0`) throughout epoch 0, otherwise the first height of `height`'s epoch
/// — the row the previous epoch's boundary hook wrote. Holds because the
/// hook writes at every boundary (see `arxd_runtime::epoch`).
pub fn validator_set_effective_height(height: u64, epoch_length: u64) -> u64 {
    epoch_of(height, epoch_length) * epoch_length.max(1)
}

/// Whether `height` is the last block of its epoch.
pub fn is_boundary(height: u64, epoch_length: u64) -> bool {
    (height + 1).is_multiple_of(epoch_length.max(1))
}

/// Per-validator power cap: twice the equal share, never below 10% and
/// never above 3,333 — so stake actually weights at small n (a plain
/// `max(10%, equal share)` collapses every set of ten or fewer to
/// one-validator-one-vote, since the cap *is* the equal share there), and
/// no single validator can ever hold the 3,334 that blocks finality on its
/// own. The equal share (rounded up) stays as a hard floor because the cap
/// must be reachable: with three validators someone has to hold 3,334.
pub fn power_cap(n: usize) -> u32 {
    let n = n.max(1) as u32;
    (2 * TOTAL_VOTING_POWER / n)
        .clamp(TOTAL_VOTING_POWER / 10, 3_333)
        .max(TOTAL_VOTING_POWER.div_ceil(n))
}

/// Assigns `TOTAL_VOTING_POWER` across `stakes` proportionally, clamping
/// anyone above `power_cap(n)` and redistributing the excess among the
/// uncapped until nobody exceeds it. Integer division's remainder goes one
/// unit at a time in ascending address order, so the result is a pure
/// function of the map. Powers always sum to exactly `TOTAL_VOTING_POWER`
/// for a non-empty input; an empty input yields an empty set.
///
/// A validator with zero stake gets zero power from the proportional pass;
/// if *every* stake is zero the total is split equally instead of dividing
/// by zero — a set nobody funded still has to be able to vote.
pub fn assign_voting_power(stakes: &BTreeMap<Address, u128>) -> BTreeMap<Address, VotingPower> {
    if stakes.is_empty() {
        return BTreeMap::new();
    }
    let cap = power_cap(stakes.len());
    let mut powers: BTreeMap<&Address, u32> = BTreeMap::new();
    let mut remaining_power = TOTAL_VOTING_POWER;
    let mut pool: BTreeMap<&Address, u128> = stakes.iter().map(|(a, s)| (a, *s)).collect();

    loop {
        let pool_total: u128 = pool.values().sum();
        // Proportional pass over whoever is still uncapped; equal split if
        // nobody in the pool has stake.
        let mut assigned: BTreeMap<&Address, u32> = BTreeMap::new();
        let mut assigned_total = 0u32;
        for (address, stake) in &pool {
            // `remaining_power ≤ 10_000` and `stake ≤ pool_total`, so the
            // product is at most 10_000 × total supply — bounded by the
            // 5 B ARX (5 × 10^18 IUM) fixed supply, ~5 × 10^22, against a
            // u128 ceiling of ~3 × 10^38. The quotient is ≤ remaining_power
            // and fits a u32 by construction.
            let share = if pool_total == 0 {
                remaining_power / pool.len() as u32
            } else {
                (u128::from(remaining_power) * stake / pool_total) as u32
            };
            assigned.insert(address, share);
            assigned_total += share;
        }
        // Remainder: one unit each, ascending address order (BTreeMap order).
        let mut leftover = remaining_power - assigned_total;
        for share in assigned.values_mut() {
            if leftover == 0 {
                break;
            }
            *share += 1;
            leftover -= 1;
        }
        // Clamp. Anyone over the cap is fixed at the cap and leaves the
        // pool; the excess is redistributed next iteration.
        let over: Vec<&Address> = assigned
            .iter()
            .filter(|(_, p)| **p > cap)
            .map(|(a, _)| *a)
            .collect();
        if over.is_empty() {
            powers.extend(assigned);
            break;
        }
        for address in over {
            powers.insert(address, cap);
            pool.remove(address);
            remaining_power -= cap;
        }
        if pool.is_empty() {
            // Everyone hit the cap: only possible when cap * n < total,
            // which `power_cap` rules out — but never loop forever on it.
            let mut leftover = remaining_power;
            for (_, p) in powers.iter_mut() {
                if leftover == 0 {
                    break;
                }
                *p += 1;
                leftover -= 1;
            }
            break;
        }
    }
    powers
        .into_iter()
        .map(|(a, p)| (a.clone(), VotingPower(p)))
        .collect()
}

/// Consensus parameters fixed at genesis and read from state at dispatch
/// time — a spec field rather than a binary constant, so two chains differ by
/// inspectable configuration and not by a magic number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    /// Seconds between block-production ticks. Every validator reads it from
    /// state, so a chain running a different cadence is a spec field, not a
    /// rebuilt binary. Only `min_validator_set`-style sanity, no floor: a
    /// test chain may legitimately want 1s.
    #[serde(default = "default_block_interval_secs")]
    pub block_interval_secs: u64,
    /// Blocks per epoch. The validator set only changes at epoch boundaries.
    #[serde(default = "default_epoch_length")]
    pub epoch_length: u64,
    /// Whether `JoinValidator` (and the boundary hook) require the validator
    /// address to carry an attestation. Off on devnet so anyone can join;
    /// on for mainnet.
    #[serde(default)]
    pub validator_attestation_required: bool,
    /// Smallest set the boundary hook will ever write. If fewer qualify the
    /// previous set is kept — never a set that cannot reach quorum.
    #[serde(default = "default_min_validator_set")]
    pub min_validator_set: usize,
    /// Largest set the boundary hook writes: the top `max_validator_set`
    /// by total stake among the eligible.
    #[serde(default = "default_max_validator_set")]
    pub max_validator_set: usize,
    /// Total `ChainRuntime::action_weight` a block may carry. A block over it
    /// is invalid (`xc_executor::AcceptBlockError::BlockOverWeight`); the
    /// producer defers what does not fit to the next block. Units are the
    /// runtime's (CoreChain: nominal microseconds on the devnet reference
    /// host — see `arxd_runtime::metering`).
    #[serde(default = "default_max_block_weight")]
    pub max_block_weight: u64,
    /// Flat per-block reward in IUM, paid to the proposer from
    /// `reward_pool_account()` (never minted — capped at what the pool holds,
    /// so total emission is bounded by the pool's genesis balance plus
    /// whatever treasury or anyone else transfers into it later). A chain
    /// param rather than a constant so it can be tapered by a genesis or
    /// governance change instead of a hard fork.
    #[serde(default = "default_reward_per_block")]
    pub reward_per_block: u128,
    /// How long unstaked coins stay locked — and slashable — before they
    /// return to the master, in blocks. Absolute rather than a multiple of
    /// `epoch_length` so retuning epochs can't silently shrink the security
    /// window. The window has to cover weak-subjectivity: a node syncing
    /// from a checkpoint older than this could be shown a chain signed by
    /// validators who have since withdrawn with nothing left to slash.
    #[serde(default = "default_unbonding_blocks")]
    pub unbonding_blocks: u64,
    /// How long a governance proposal accepts votes, in blocks from
    /// submission (`circuit-governance`).
    #[serde(default = "default_voting_period_blocks")]
    pub voting_period_blocks: u64,
    /// Yes-power a proposal needs to pass, in basis points of
    /// `TOTAL_VOTING_POWER` — on top of yes > no. Ties every passing
    /// proposal to a real share of the set, not just a majority of whoever
    /// turned up.
    #[serde(default = "default_proposal_quorum_bps")]
    pub proposal_quorum_bps: u32,
    /// Flat per-action fee in IUM; the full fee is
    /// `action_fee + weight × weight_fee` (`arxd_runtime::metering`).
    /// Governable so a fee-market problem is a vote, not a coordinated
    /// release — two nodes disagreeing on the fee fork the chain.
    #[serde(default = "default_action_fee")]
    pub action_fee: u128,
    /// IUM per weight unit on top of `action_fee`.
    #[serde(default = "default_weight_fee")]
    pub weight_fee: u128,
    /// Smallest self-stake `JoinValidator` accepts, in IUM. Without a floor
    /// "becoming a validator" would be free.
    #[serde(default = "default_min_validator_stake")]
    pub min_validator_stake: u128,
    /// Share of a double-signer's stake burned, in bps. Whitepaper §9.3:
    /// the full stake — equivocation is deliberate and attributable.
    #[serde(default = "default_equivocation_slash_bps")]
    pub equivocation_slash_bps: u32,
    /// Share of a validator's stake burned per missed slot, in bps.
    #[serde(default = "default_downtime_slash_bps")]
    pub downtime_slash_bps: u32,
    /// Block-fee split, in bps: the proposer's cut and the treasury's cut;
    /// the remainder is burned by never being credited.
    #[serde(default = "default_fee_proposer_bps")]
    pub fee_proposer_bps: u32,
    #[serde(default = "default_fee_treasury_bps")]
    pub fee_treasury_bps: u32,
}

fn default_block_interval_secs() -> u64 {
    2
}
fn default_epoch_length() -> u64 {
    1_800
}
fn default_min_validator_set() -> usize {
    4
}
fn default_max_validator_set() -> usize {
    100
}
/// ~1s of reference execution per block at CoreChain's table, well under a
/// 2s devnet slot.
fn default_max_block_weight() -> u64 {
    1_000_000
}
/// 4.3 ARX/block in IUM — whitepaper §9.1/9.3 Y1 target. With 2s slots a
/// 750M-ARX pool lasts ~11 years at this rate.
pub const DEFAULT_REWARD_PER_BLOCK: u128 = 4_300_000_000;
fn default_reward_per_block() -> u128 {
    DEFAULT_REWARD_PER_BLOCK
}
/// 14 days at 2s slots — whitepaper §5.6. Between the sub-3-day chains that
/// don't slash (Solana, Near) and the 21/28-day ones (Cosmos, Polkadot)
/// whose length is partly there to fit a human evidence-submission window
/// and a governance voting period; Arxium detects equivocation in-process
/// and has neither, so the weak-subjectivity margin is what's left to cover.
pub const DEFAULT_UNBONDING_BLOCKS: u64 = 14 * 24 * 60 * 60 / 2;
fn default_unbonding_blocks() -> u64 {
    DEFAULT_UNBONDING_BLOCKS
}

/// 7 days at 2s slots.
fn default_voting_period_blocks() -> u64 {
    7 * 24 * 60 * 60 / 2
}
/// Half the set's power must say yes.
fn default_proposal_quorum_bps() -> u32 {
    5_000
}

pub const DEFAULT_ACTION_FEE: u128 = 1_000_000;
fn default_action_fee() -> u128 {
    DEFAULT_ACTION_FEE
}
/// At CoreChain's weight table a `Transfer` (weight 50) costs
/// `ACTION_FEE + 50 × WEIGHT_FEE` = 0.0015 ARX.
pub const DEFAULT_WEIGHT_FEE: u128 = 10_000;
fn default_weight_fee() -> u128 {
    DEFAULT_WEIGHT_FEE
}
/// 100,000 ARX in IUM.
pub const DEFAULT_MIN_VALIDATOR_STAKE: u128 = 100_000 * 1_000_000_000;
fn default_min_validator_stake() -> u128 {
    DEFAULT_MIN_VALIDATOR_STAKE
}
fn default_equivocation_slash_bps() -> u32 {
    10_000
}
/// 0.01% per missed slot — a real deterrent over an epoch, survivable for
/// one flaky restart.
fn default_downtime_slash_bps() -> u32 {
    1
}
fn default_fee_proposer_bps() -> u32 {
    3_000
}
fn default_fee_treasury_bps() -> u32 {
    2_000
}

impl Default for ChainParams {
    fn default() -> Self {
        Self {
            block_interval_secs: default_block_interval_secs(),
            epoch_length: default_epoch_length(),
            validator_attestation_required: false,
            min_validator_set: default_min_validator_set(),
            max_validator_set: default_max_validator_set(),
            max_block_weight: default_max_block_weight(),
            reward_per_block: default_reward_per_block(),
            unbonding_blocks: default_unbonding_blocks(),
            voting_period_blocks: default_voting_period_blocks(),
            proposal_quorum_bps: default_proposal_quorum_bps(),
            action_fee: default_action_fee(),
            weight_fee: default_weight_fee(),
            min_validator_stake: default_min_validator_stake(),
            equivocation_slash_bps: default_equivocation_slash_bps(),
            downtime_slash_bps: default_downtime_slash_bps(),
            fee_proposer_bps: default_fee_proposer_bps(),
            fee_treasury_bps: default_fee_treasury_bps(),
        }
    }
}

/// What a governance proposal does when it passes and is executed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Replace the whole `chain_params` row. Whole-row rather than per-field
    /// so the proposal text is exactly the state that results — a supervisor
    /// reads one record, not a diff against something that may have moved.
    SetChainParams(ChainParams),
    /// Rotate one of the genesis-seeded admin roles (`AdminKey`). `role` is
    /// the `AdminRole` name (`"attestor"`, `"freeze"`, `"recovery"`) — a
    /// string so this crate needn't depend on `xc-circuit`, which defines
    /// the enum and depends on this crate.
    SetAdmin { role: String, address: Address },
    /// Pay `amount` IUM out of `treasury_account()` to `to`.
    TreasurySpend { to: Address, amount: u128 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Accepting votes until `voting_ends_at`.
    Open,
    /// Window closed, passed, and its action applied.
    Executed,
    /// Window closed and it did not pass (or its action failed to apply —
    /// e.g. the treasury no longer held the amount).
    Rejected,
}

/// One governance proposal (`circuit-governance`). Stored at `ProposalKey`
/// in `CF_GOVERNANCE`, merkleized: whether a param change was legitimately
/// voted in is exactly what an adjudicator would need to prove.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub action: GovernanceAction,
    /// Free-text rationale, bounded by the runtime. Rides in state so the
    /// record a supervisor pulls carries the justification with it.
    pub description: String,
    pub created_at: u64,
    pub voting_ends_at: u64,
    /// Summed `VotingPower` (bps of `TOTAL_VOTING_POWER`) as of the set in
    /// force when each vote landed.
    pub yes_power: u32,
    pub no_power: u32,
    pub status: ProposalStatus,
}

/// Where a validator stands with respect to the active set. Written by the
/// staking dispatch (`Pending`/`Leaving`), the fault paths (`Jailed`/
/// `Tombstoned`), and the epoch-boundary hook (`Active`, and clearing
/// `Leaving`). Merkleized state — it gates who may be in the next set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// In the current set.
    Active,
    /// Staked and keyed, waiting for the next boundary.
    Pending,
    /// Excluded from every set until `until_epoch` (inclusive of the
    /// boundary that starts it), then eligible again.
    Jailed { until_epoch: u64 },
    /// Keeps voting until the boundary of `from_epoch - 1`, then is dropped.
    Leaving { from_epoch: u64 },
    /// Permanently out. Address-scoped: no amount of new stake re-admits it.
    Tombstoned,
}

impl ValidatorStatus {
    /// Whether this validator may be included in the set that starts at
    /// `next_epoch`.
    pub fn eligible_for(&self, next_epoch: u64) -> bool {
        match self {
            ValidatorStatus::Active | ValidatorStatus::Pending => true,
            ValidatorStatus::Jailed { until_epoch } => next_epoch >= *until_epoch,
            ValidatorStatus::Leaving { from_epoch } => next_epoch < *from_epoch,
            ValidatorStatus::Tombstoned => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from_pubkey_bytes(&[n; 32]).unwrap()
    }

    fn stakes(list: &[(u8, u128)]) -> BTreeMap<Address, u128> {
        list.iter().map(|(n, s)| (addr(*n), *s)).collect()
    }

    fn total(set: &BTreeMap<Address, VotingPower>) -> u32 {
        set.values().map(|p| p.0).sum()
    }

    fn check_invariants(set: &BTreeMap<Address, VotingPower>) {
        assert_eq!(total(set), TOTAL_VOTING_POWER, "{set:?}");
        let cap = power_cap(set.len());
        for (a, p) in set {
            assert!(p.0 <= cap, "{a} has {} over cap {cap}", p.0);
        }
    }

    #[test]
    fn epoch_arithmetic() {
        assert_eq!(epoch_of(0, 10), 0);
        assert_eq!(epoch_of(9, 10), 0);
        assert_eq!(epoch_of(10, 10), 1);
        assert_eq!(boundary_of(0, 10), 9);
        assert_eq!(boundary_of(1, 10), 19);
        assert!(is_boundary(9, 10));
        assert!(!is_boundary(10, 10));
        assert!(is_boundary(19, 10));
        // A zero epoch length is nonsense; treat it as 1 rather than divide by zero.
        assert_eq!(epoch_of(7, 0), 7);
    }

    #[test]
    fn cap_is_twice_the_equal_share_bounded_by_ten_percent_and_the_blocking_threshold() {
        assert_eq!(power_cap(1), 10_000);
        assert_eq!(power_cap(2), 5_000);
        assert_eq!(power_cap(3), 3_334, "someone must hold 3,334 at n=3");
        assert_eq!(power_cap(4), 3_333);
        assert_eq!(power_cap(6), 3_333);
        assert_eq!(power_cap(7), 2_857);
        assert_eq!(power_cap(10), 2_000);
        assert_eq!(power_cap(20), 1_000);
        assert_eq!(power_cap(100), 1_000);
        // Reachable everywhere: n × cap ≥ total.
        for n in 1..=200usize {
            assert!(n as u32 * power_cap(n) >= TOTAL_VOTING_POWER, "n={n}");
        }
        // Nobody can block finality alone once there are four or more.
        for n in 4..=200usize {
            assert!(
                power_cap(n) < TOTAL_VOTING_POWER - QUORUM_POWER + 1,
                "n={n}"
            );
        }
    }

    #[test]
    fn stake_weights_at_small_n() {
        // Six validators 5/4/3/2/1/1: no longer collapses to one-vote-each.
        let set = assign_voting_power(&stakes(&[(1, 5), (2, 4), (3, 3), (4, 2), (5, 1), (6, 1)]));
        check_invariants(&set);
        assert_eq!(set[&addr(1)], VotingPower(3_125));
        assert_eq!(set[&addr(2)], VotingPower(2_500));
        assert_eq!(set[&addr(6)], VotingPower(625));
        assert!(set[&addr(1)] > set[&addr(2)] && set[&addr(2)] > set[&addr(3)]);
    }

    #[test]
    fn empty_and_single() {
        assert!(assign_voting_power(&BTreeMap::new()).is_empty());
        let set = assign_voting_power(&stakes(&[(1, 5)]));
        assert_eq!(set[&addr(1)], VotingPower(10_000));
    }

    #[test]
    fn equal_stakes_split_evenly_with_remainder_to_lowest_addresses() {
        let set = assign_voting_power(&stakes(&[(1, 7), (2, 7), (3, 7)]));
        check_invariants(&set);
        let mut powers: Vec<u32> = set.values().map(|p| p.0).collect();
        powers.sort();
        assert_eq!(powers, vec![3_333, 3_333, 3_334]);
        // The extra unit went to the lowest address.
        let first = set.keys().next().unwrap();
        assert_eq!(set[first].0, 3_334);
    }

    #[test]
    fn all_zero_stakes_split_equally() {
        let set = assign_voting_power(&stakes(&[(1, 0), (2, 0), (3, 0), (4, 0)]));
        check_invariants(&set);
        assert!(set.values().all(|p| p.0 == 2_500));
    }

    #[test]
    fn whale_lands_exactly_at_cap_and_the_rest_absorb_the_excess() {
        // 20 validators: cap binds at 1,000. One holds 99%.
        let mut list = vec![(1u8, 99_000u128)];
        list.extend((2..=20).map(|n| (n, 100u128)));
        let set = assign_voting_power(&stakes(&list));
        check_invariants(&set);
        assert_eq!(set[&addr(1)], VotingPower(1_000));
        // The other nineteen share the remaining 9,000: 473 or 474 each.
        assert!((2..=20).all(|n| (473..=474).contains(&set[&addr(n)].0)));
    }

    #[test]
    fn cascading_caps_terminate_and_stay_exact() {
        // Two whales, then the cap re-binds on the next tier (20 validators, cap 1,000).
        let list: Vec<(u8, u128)> =
            vec![(1, 50_000), (2, 40_000), (3, 5_000), (4, 3_000), (5, 1_000)]
                .into_iter()
                .chain((6..=20).map(|n| (n, 10)))
                .collect();
        let set = assign_voting_power(&stakes(&list));
        check_invariants(&set);
        for n in 1..=5 {
            assert_eq!(set[&addr(n)], VotingPower(1_000), "{n}");
        }
        assert!((6..=20).all(|n| (333..=334).contains(&set[&addr(n)].0)));
    }

    #[test]
    fn set_sizes_from_one_to_one_hundred_all_sum_exactly() {
        for n in [1usize, 2, 3, 4, 6, 10, 11, 37, 100] {
            let list: Vec<(u8, u128)> = (0..n as u8)
                .map(|i| (i, 1 + (i as u128 * 7919) % 1000))
                .collect();
            let set = assign_voting_power(&stakes(&list));
            assert_eq!(set.len(), n);
            check_invariants(&set);
        }
    }

    #[test]
    fn pure_function_of_the_map_regardless_of_insertion_order() {
        let a = stakes(&[(9, 100), (3, 5_000), (7, 42), (1, 900)]);
        let b = stakes(&[(1, 900), (7, 42), (3, 5_000), (9, 100)]);
        assert_eq!(assign_voting_power(&a), assign_voting_power(&b));
    }

    #[test]
    fn quorum_counts_power_not_heads_and_ignores_outsiders() {
        // 4 validators, one with 70% of stake — cap is 3,333 so it lands there
        // and can never block alone; the other three split 6,667.
        let set = assign_voting_power(&stakes(&[(1, 70), (2, 10), (3, 10), (4, 10)]));
        check_invariants(&set);
        assert_eq!(set[&addr(1)], VotingPower(3_333));
        // The three small ones together hold exactly quorum.
        assert!(quorum_reached(&set, [&addr(2), &addr(3), &addr(4)]));
        // Whale plus one small: ~5,556 < 6,667.
        assert!(!quorum_reached(&set, [&addr(1), &addr(2)]));
        // Non-member and duplicates count for nothing.
        assert_eq!(
            signed_power(&set, [&addr(2), &addr(2), &addr(99)]),
            set[&addr(2)].0
        );
    }

    #[test]
    fn majority_by_count_can_be_below_quorum_by_power() {
        // 8 validators, cap 2,500: three big ones clamp to the cap (7,500)
        // and the five tiny ones share 2,500. Five of eight by head-count is
        // a quarter of the power; three of eight is quorum.
        let set = assign_voting_power(&stakes(&[
            (1, 1000),
            (2, 1000),
            (3, 1000),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 1),
        ]));
        check_invariants(&set);
        let tiny: Vec<Address> = (4..=8).map(addr).collect();
        assert!(!quorum_reached(&set, tiny.iter()));
        assert!(quorum_reached(&set, [&addr(1), &addr(2), &addr(3)]));
        assert!(!quorum_reached(&set, tiny.iter().chain([&addr(1)])));
    }

    #[test]
    fn six_validators_do_not_break_the_cap() {
        let set = assign_voting_power(&stakes(&[(1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1)]));
        check_invariants(&set);
    }

    #[test]
    fn status_eligibility() {
        assert!(ValidatorStatus::Active.eligible_for(5));
        assert!(ValidatorStatus::Pending.eligible_for(5));
        assert!(!ValidatorStatus::Jailed { until_epoch: 6 }.eligible_for(5));
        assert!(ValidatorStatus::Jailed { until_epoch: 6 }.eligible_for(6));
        assert!(ValidatorStatus::Leaving { from_epoch: 6 }.eligible_for(5));
        assert!(!ValidatorStatus::Leaving { from_epoch: 6 }.eligible_for(6));
        assert!(!ValidatorStatus::Tombstoned.eligible_for(u64::MAX));
    }
}
