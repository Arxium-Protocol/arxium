// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `ChainRuntime`: everything `arxd/node` needs to know about a chain's state
//! transition, bundled so the node can be generic over it. CoreChain
//! implements this in `arxd/runtime`; a Spoke Chain implements it in its own
//! crate and gets the whole node — networking, RPC, finality, produce loop —
//! for free.
//!
//! This is a *code* contract in the direction Spoke -> node, never Spoke ->
//! CoreChain: a Spoke Chain implements this trait and imports nothing from
//! `arxd/runtime`. What ties a Spoke to CoreChain is protocol (state-root
//! submission, shared validators), not the build graph.
//!
//! Lives in its own crate rather than `xc-primitives`: it needs `ArxiumDb`
//! (`xc-storage`) and `BlockUpdates` (`xc-executor`), both of which already
//! depend on `xc-primitives` — putting the trait there would be a dependency
//! cycle.
//!
//! No `write_genesis` hook, deliberately: genesis writing
//! (`arxd_genesis::write_plain`/`write_raw`, called directly from
//! `arxd-node`'s `new_partial`) registers the BLS keys that `arxd-node`'s
//! finality subsystem needs to reach quorum, and that subsystem runs
//! identically for every `ChainRuntime` implementor — it is not something a
//! runtime opts into. BLS finality is a node-level contract in this
//! codebase, not a per-runtime choice, so genesis writing stays a node-level
//! concern rather than a trait method a runtime could override or skip.

use xc_evidence::EquivocationEvidence;
use serde::{Serialize, de::DeserializeOwned};
use xc_chain_spec::presets::PresetRegistry;
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address};
use xc_storage::{ArxiumDb, BlockView, StorageError};

/// Everything `ChainRuntime::dispatch` needs about the block it's executing
/// into. One struct instead of a flat parameter list so a future field
/// (another lookup, another piece of block context) is a non-breaking
/// addition for every Spoke Chain implementor instead of a signature change.
///
/// `operator_lookup`/`operator_validators_lookup` stay as fields rather than
/// being dropped in favor of `db` directly: they're overlay-aware (checking
/// this block's not-yet-committed `AuthorizeOperator`/`RevokeOperator`
/// changes before falling through to `db`), the same guarantee
/// `view`/`AccountUpdates`/`StakeUpdates` give same-block actions elsewhere
/// in this executor. A `db`-only lookup would silently stop seeing an
/// operator grant made earlier in the same block.
pub struct DispatchCtx<'a> {
    pub view: &'a BlockView<'a>,
    pub db: &'a ArxiumDb,
    pub operator_lookup: &'a dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    pub operator_validators_lookup: &'a dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    pub validators: &'a [Address],
    pub height: u64,
}

pub trait ChainRuntime: Send + Sync + 'static {
    /// Fills in `P` in `Action<P>` / `Block<P>`.
    type Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static;

    /// This chain's built-in genesis presets (`--chain devnet` etc). CoreChain
    /// returns its `devnet`/`local` presets; a Spoke Chain with no official
    /// network of its own returns `&PresetRegistry::EMPTY` — `--chain <path>`
    /// still works either way. Keeps `arxd/node` free of any specific chain's
    /// genesis data: it resolves `--chain` through whatever `R::presets()`
    /// hands it, never a hardcoded registry.
    fn presets() -> &'static PresetRegistry;

    /// Flat fee charged per action, in base units.
    fn action_fee() -> u128;

    /// Minimum self-stake for a validator, if this chain has validator
    /// staking at all. `None` disables the RPC's stake hint.
    fn min_validator_stake() -> Option<u128>;

    /// Cheap rejection before an action reaches the mempool, so a doomed
    /// action fails at submission with a real reason instead of being
    /// silently dropped at dispatch.
    fn admission_precheck(action: &Action<Self::Payload>, db: &ArxiumDb) -> anyhow::Result<()>;

    /// The state transition. Takes `ctx.db` directly rather than pre-baked
    /// lookup closures for everything, so a generic node never needs to know
    /// what a given runtime looks up (e.g. CoreChain's evidence/BLS-owner
    /// checks).
    fn dispatch(action: &Action<Self::Payload>, ctx: &DispatchCtx<'_>) -> anyhow::Result<BlockUpdates>;

    /// Runs once per block, after every action in it has been dispatched.
    /// This is where a chain applies whole-block economics — block rewards,
    /// downtime slashing — that aren't tied to any single action. CoreChain
    /// moves its `circuit_staking` reward/slash calls here; a chain with no
    /// block-level economics (e.g. `toy-chain`) returns `BlockUpdates::default()`.
    fn on_block_sealed(
        view: &BlockView<'_>,
        proposer: &Address,
        fees_collected: u128,
        validators: &[Address],
        height: u64,
    ) -> anyhow::Result<BlockUpdates>;

    /// Builds the action that reports an equivocation, or `None` if this
    /// chain has no equivocation slashing — in which case the node skips the
    /// evidence watcher entirely. Every Arxium chain does *not* necessarily
    /// have equivocation slashing: that is CoreChain's, since it's the one
    /// with BLS-key registration and stake to slash. `toy-chain` returns
    /// `None`.
    fn build_evidence_action(
        evidence: EquivocationEvidence<Self::Payload>,
        sender: &Address,
        nonce: u64,
    ) -> Option<Action<Self::Payload>>;

    /// Implements `arxd pair` / `arxd pair --revoke`: signs and submits this
    /// chain's operator-authorization action over HTTP. `seed`/`sender` are
    /// the validator's already-loaded signing key material (chain-agnostic,
    /// loaded by `arxd-node`). Defaults to unsupported — `pair` builds a
    /// chain-specific action (CoreChain's `AuthorizeOperator`/
    /// `RevokeOperator`), so a Spoke Chain with no equivalent action just
    /// doesn't get the subcommand rather than POSTing a payload its own
    /// runtime can't decode.
    fn pair(
        _seed: &[u8; 32],
        _sender: &Address,
        _node: &str,
        _token: Option<&str>,
        _revoke: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("this chain does not support `pair`")
    }
}
