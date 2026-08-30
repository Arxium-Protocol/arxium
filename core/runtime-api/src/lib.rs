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

use xc_evidence::EquivocationEvidence;
use serde::{Serialize, de::DeserializeOwned};
use xc_chain_spec::presets::PresetRegistry;
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address};
use xc_storage::{ArxiumDb, BlockView, StorageError};

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

    /// The state transition. Takes `db` directly rather than pre-baked
    /// lookup closures, so a generic node never needs to know what a given
    /// runtime looks up (e.g. CoreChain's evidence/BLS-owner checks).
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        action: &Action<Self::Payload>,
        view: &BlockView<'_>,
        db: &ArxiumDb,
        operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        validators: &[Address],
        current_height: u64,
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
}
