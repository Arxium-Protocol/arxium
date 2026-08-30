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
use runtime_api::ChainRuntime;
use serde::{Deserialize, Serialize};
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address, ValidatorChange};
use xc_storage::{AccountUpdates, ArxiumDb, BlockView, StorageError};

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
) -> anyhow::Result<(AccountUpdates, Option<ValidatorChange>)> {
    let updates = match &action.payload {
        RwaPayload::Issue { amount } => {
            circuit_rwa_asset::apply_issue(view, issuer, &action.sender, action.nonce, *amount)?
        }
        RwaPayload::Transfer { to, amount } => circuit_rwa_asset::apply_compliant_transfer(
            view,
            &action.sender,
            action.nonce,
            to,
            *amount,
        )?,
    };
    Ok((updates, None))
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

    fn dispatch(
        action: &RwaAction,
        view: &BlockView<'_>,
        _db: &ArxiumDb,
        _operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        _operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        _validators: &[Address],
        _current_height: u64,
    ) -> anyhow::Result<BlockUpdates> {
        let issuer = Address::parse(ISSUER).expect("ISSUER is a valid address");
        let (accounts, validator_change) = dispatch(action, view, &issuer)?;
        Ok(BlockUpdates {
            accounts,
            validator_change,
            ..Default::default()
        })
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
    node::run::<ToyRuntime>()
}
