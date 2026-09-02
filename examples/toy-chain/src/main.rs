// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Toy Chain: RWA (real-world-asset) sovereign chain MVP built purely on
//! `core/` + `circuits/rwa-asset`, running on the real `arxd/node` (networking,
//! RPC, finality) via `ChainRuntime`, with no dependency on `arxd/runtime`
//! (CoreChain's runtime). It exists to answer one question honestly: does the
//! `core/` design (generic `Action<P>`/`Block<P>`, dispatch-closure executor)
//! actually hold up for a chain with *different* execution semantics than
//! CoreChain's plain `Transfer`? So its payload is its own `RwaPayload`
//! (`Issue`, compliance-gated `Transfer`), not CoreChain's.
//!
//! Boot with `--chain examples/toy-chain/specs/toy-chain-dev.json` — the
//! fixed genesis accounts (issuer, KYC'd recipient, non-KYC'd recipient) live
//! there, same shared chain-spec path CoreChain's `devnet`/`local` presets use.

use anyhow::Result;
use xc_runtime_api::ChainRuntime;
use serde::{Deserialize, Serialize};
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address, Asset, ValidatorChange};
use xc_storage::{AccountUpdates, ArxiumDb, AssetBalanceUpdates, BlockView};

/// toy-chain has no `RegisterAsset` action or registry — there is exactly
/// one implicit asset, constructed fresh on every dispatch rather than
/// looked up. `circuits/rwa-asset` takes a caller-resolved `&Asset` for
/// exactly this reason: CoreChain backs it with a real `meta:asset:{id}`
/// registry, toy-chain doesn't need one.
fn toy_asset(issuer: &Address) -> Asset {
    Asset { asset_id: "toy".into(), issuer: issuer.clone(), compliance_required: true }
}

/// The RWA chain's own action set — distinct from CoreChain's `ActionPayload`
/// in `arxd/runtime`, proving payloads are chain-specific rather than one
/// shared enum.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum RwaPayload {
    Issue { amount: u128 },
    Transfer { to: Address, amount: u128 },
}

type RwaAction = Action<RwaPayload>;

/// Fixed genesis issuer — `identity_hash: "kyc-issuer"` in
/// `specs/toy-chain-dev.json`, derived from `SigningKey::from_bytes(&[1u8; 32])`.
const ISSUER: &str = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";

fn dispatch(
    action: &RwaAction,
    view: &BlockView<'_>,
    issuer: &Address,
) -> anyhow::Result<(AccountUpdates, AssetBalanceUpdates, Option<ValidatorChange>)> {
    let asset = toy_asset(issuer);
    let (accounts, assets) = match &action.payload {
        RwaPayload::Issue { amount } => {
            circuit_rwa_asset::apply_issue(view, &asset, &action.sender, action.nonce, *amount)?
        }
        RwaPayload::Transfer { to, amount } => circuit_rwa_asset::apply_compliant_transfer(
            view,
            &asset,
            &action.sender,
            action.nonce,
            to,
            *amount,
        )?,
    };
    Ok((accounts, assets, None))
}

struct ToyRuntime;

impl ChainRuntime for ToyRuntime {
    type Payload = RwaPayload;

    /// No official toy-chain network to embed — `--chain
    /// examples/toy-chain/specs/toy-chain-dev.json` only.
    fn presets() -> &'static xc_chain_spec::presets::PresetRegistry {
        &xc_chain_spec::presets::PresetRegistry::EMPTY
    }

    fn action_fee() -> u128 {
        0
    }

    fn min_validator_stake() -> Option<u128> {
        None
    }

    fn admission_precheck(_action: &RwaAction, _db: &ArxiumDb) -> anyhow::Result<()> {
        Ok(())
    }

    fn dispatch(action: &RwaAction, ctx: &xc_runtime_api::DispatchCtx<'_>) -> anyhow::Result<BlockUpdates> {
        let issuer = Address::parse(ISSUER).expect("ISSUER is a valid address");
        let (accounts, assets, validator_change) = dispatch(action, ctx.view, &issuer)?;
        Ok(BlockUpdates {
            accounts,
            assets,
            validator_change,
            ..Default::default()
        })
    }

    // toy-chain has no block-level economics of its own (no reward pool, no
    // downtime slash) — CoreChain's are not something a Spoke Chain opts
    // into by default.
    fn on_block_sealed(
        _view: &BlockView<'_>,
        _proposer: &Address,
        _fees_collected: u128,
        _validators: &[Address],
        _height: u64,
    ) -> anyhow::Result<BlockUpdates> {
        Ok(BlockUpdates::default())
    }

    // toy-chain has no evidence-reporting action — it exists to exercise
    // `core`'s generic boundaries, not to be a second real chain.
    fn build_evidence_action(
        _evidence: xc_evidence::EquivocationEvidence<RwaPayload>,
        _sender: &Address,
        _nonce: u64,
    ) -> Option<RwaAction> {
        None
    }
}

fn main() -> Result<()> {
    arxd_node::run::<ToyRuntime>()
}

#[cfg(test)]
mod tests {
    use super::ToyRuntime;
    use xc_runtime_api::ChainRuntime;

    /// toy-chain has no built-in presets (`ToyRuntime::presets()` is
    /// `PresetRegistry::EMPTY`) — CoreChain's `devnet`/`local` names must
    /// stay CoreChain-only, not silently resolve for a Spoke Chain node
    /// that boots on unrelated genesis state. Regression test for the bug
    /// this crate exists to catch: presets leaking across runtimes.
    #[test]
    fn devnet_preset_is_not_available_to_toy_chain() {
        assert!(xc_chain_spec::resolve_chain_spec("devnet", ToyRuntime::presets()).is_err());
    }
}
