// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! CoreChain's state transition function: `ActionPayload` and `dispatch`.
//!
//! **Do not add this crate as a dependency of the Retracer.** It is
//! CoreChain-specific by design — a different chain defines its own payload
//! type and dispatch table (see `examples/toy-chain`). A Retracer that
//! imports it becomes permanently CoreChain-only, defeating the "any Spoke
//! Chain, no code required" goal. The Retracer's path to reading arbitrary
//! chains is a self-describing wire format, not typed imports of a specific
//! chain's runtime.

mod account;
pub mod adjudicate;
mod asset;
mod consensus;
mod epoch;
#[cfg(test)]
mod epoch_tests;
mod identity;
pub mod metering;
mod pair;
mod specs;
mod staking;

pub use staking::MIN_VALIDATOR_STAKE;

use xc_bls::BlsPublicKey;
use xc_chain_spec::presets::PresetRegistry;
use xc_circuit::{AccountKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address};
use xc_storage::{ArxiumDb, BlockView, StorageError};

pub use arxd_payload::{ActionPayload, ChainAction, ChainBlock};

/// CoreChain's `ChainRuntime` implementation — see `xc_runtime_api::ChainRuntime`
/// for what this makes `arxd/node` generic over.
pub struct CoreChainRuntime;

impl xc_runtime_api::ChainRuntime for CoreChainRuntime {
    type Payload = ActionPayload;

    fn presets() -> &'static PresetRegistry {
        &specs::CORECHAIN_PRESETS
    }

    fn action_fee() -> u128 {
        ACTION_FEE
    }

    fn action_weight(action: &ChainAction) -> u64 {
        metering::action_weight(action)
    }

    fn action_fee_for(weight: u64) -> u128 {
        metering::action_fee_for(weight)
    }

    fn min_validator_stake() -> Option<u128> {
        Some(MIN_VALIDATOR_STAKE)
    }

    fn admission_precheck(action: &ChainAction, db: &ArxiumDb) -> anyhow::Result<()> {
        admission_precheck(action, db)
    }

    fn dispatch(
        action: &ChainAction,
        ctx: &xc_runtime_api::DispatchCtx<'_>,
    ) -> anyhow::Result<BlockUpdates> {
        dispatch(
            action,
            ctx.view,
            ctx.operator_lookup,
            ctx.operator_validators_lookup,
            ctx.validators,
            ctx.height,
            // Through the view (overlay + touched-key recording), not `db`.
            &|pk: &BlsPublicKey| ctx.view.get(&xc_circuit::BlsPubkeyOwnerKey(pk)),
        )
    }

    /// Whole-block economics: reward split plus §7.3 downtime slash. Moved
    /// here (from what used to be hardcoded in `arxd/node/src/produce.rs`
    /// and `xc_executor::accept_block`) so a chain without CoreChain's
    /// staking model — e.g. `toy-chain` — never has these applied to its
    /// state root.
    fn on_block_sealed(
        view: &BlockView<'_>,
        proposer: &Address,
        fees_collected: u128,
        validators: &[Address],
        height: u64,
    ) -> anyhow::Result<BlockUpdates> {
        let params = view.get(&xc_circuit::ChainParamsKey)?.unwrap_or_default();
        let reward_updates = circuit_staking::apply_block_reward(
            view,
            proposer,
            fees_collected,
            params.reward_per_block,
        )?;
        let mut updates = BlockUpdates {
            accounts: reward_updates,
            ..Default::default()
        };
        if let Some(primary) = xc_primitives::expected_proposer(validators, height) {
            let (downtime_accounts, downtime_stakes) =
                circuit_staking::apply_downtime_slash(view, &primary, proposer, height)?;
            // A missed slot that actually cost stake also jails: out of the
            // set from the next boundary, back the epoch after. Tombstoned
            // stays tombstoned; a jail already running is left alone.
            if !downtime_stakes.allocations.is_empty() {
                let epoch_length = params.epoch_length;
                let jailed = xc_primitives::ValidatorStatus::Jailed {
                    until_epoch: xc_primitives::epoch_of(height, epoch_length) + 2,
                };
                match view.get(&xc_circuit::ValidatorStatusKey(&primary))? {
                    Some(xc_primitives::ValidatorStatus::Tombstoned)
                    | Some(xc_primitives::ValidatorStatus::Jailed { .. }) => {}
                    _ => {
                        updates
                            .validator_statuses
                            .0
                            .insert(primary.clone(), Some(jailed));
                    }
                }
            }
            updates.accounts.0.extend(downtime_accounts.0);
            updates
                .stakes
                .allocations
                .extend(downtime_stakes.allocations);
            updates
                .stakes
                .validator_index
                .extend(downtime_stakes.validator_index);
        }
        // Epoch boundary: the one place the set changes. Runs last so it
        // sees this block's slash/jail above through the same view.
        let boundary = epoch::boundary_hook(view, height)?;
        updates
            .validator_statuses
            .0
            .extend(boundary.validator_statuses.0);
        updates.validator_set = boundary.validator_set;
        Ok(updates)
    }

    fn build_evidence_action(
        evidence: xc_evidence::EquivocationEvidence<ActionPayload>,
        sender: &Address,
        nonce: u64,
    ) -> Option<ChainAction> {
        Some(Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: ActionPayload::SubmitEquivocationEvidence {
                block_a: Box::new(evidence.block_a),
                block_b: Box::new(evidence.block_b),
            },
        })
    }

    fn build_execution_fault_action(
        artifact_json: String,
        sender: &Address,
        nonce: u64,
    ) -> Option<ChainAction> {
        Some(Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload: ActionPayload::SubmitExecutionFault { artifact_json },
        })
    }

    fn locally_adjudicate_execution_fault(artifact_json: &str) -> Option<String> {
        let artifact: xc_artifact::EvidenceArtifact = serde_json::from_str(artifact_json).ok()?;
        let outcome = match &artifact.fault {
            xc_artifact::Fault::ActionDivergence { .. } => {
                adjudicate::adjudicate_action_divergence(&artifact).ok()?
            }
            xc_artifact::Fault::BlockDivergence { .. } => {
                adjudicate::adjudicate_block_divergence(&artifact).ok()?
            }
            // Neither is an execution fault: both are settled by signature
            // checks alone (`xc_artifact::verify`), with nothing for the
            // adjudicator to replay.
            xc_artifact::Fault::Equivocation { .. }
            | xc_artifact::Fault::PrecommitEquivocation { .. }
            | xc_artifact::Fault::ExecutionDisagreement { .. } => return None,
        };
        match outcome {
            adjudicate::AdjudicationOutcome::Culpable { culpable_pubkey } => Some(culpable_pubkey),
            adjudicate::AdjudicationOutcome::Disagreement { .. } => None,
        }
    }

    fn pair(
        seed: &[u8; 32],
        sender: &Address,
        node: &str,
        token: Option<&str>,
        revoke: bool,
    ) -> anyhow::Result<()> {
        pair::run(seed, sender, node, token, revoke)
    }
}

/// Cheap pre-check for the payload variants whose `dispatch` rejection
/// reason (bad `is_authorized`, below `MIN_VALIDATOR_STAKE`, not a current
/// validator) previously only surfaced during block production — the
/// action would just silently vanish from the mempool with no way for the
/// submitter to find out why. Runs the same authorization/minimum-stake
/// logic `dispatch` enforces, straight against current chain state, so an RPC
/// submission or gossip receipt (via `xc_mempool::PayloadPrecheck`) can
/// both reject with the real reason immediately instead of a false 202.
///
/// Not a full re-implementation of `dispatch` — this only covers checks that
/// don't depend on same-block ordering. Anything it misses (e.g. a
/// same-block race between two actions) is still caught, just later, by
/// `dispatch` itself, which remains the authoritative check.
pub fn admission_precheck(action: &ChainAction, db: &ArxiumDb) -> anyhow::Result<()> {
    let balance = db
        .get_account(&action.sender)?
        .map(|e| e.balance)
        .unwrap_or(0);
    let weight = metering::action_weight(action);
    let max_block_weight = db.chain_params()?.max_block_weight;
    if weight > max_block_weight {
        anyhow::bail!(
            "action weight {weight} exceeds max_block_weight {max_block_weight} and can never be included"
        );
    }
    let fee = metering::action_fee_for(weight);
    if balance < fee {
        anyhow::bail!("insufficient balance for the action fee ({fee} IUM)");
    }
    let operator_lookup = |validator: &Address| db.get_operator(validator);
    match &action.payload {
        ActionPayload::JoinValidator {
            validator,
            stake,
            bls_pubkey,
            bls_pop,
        } => {
            if !staking::is_authorized(&action.sender, validator, &operator_lookup)? {
                anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
            }
            staking::check_join_admission(db, validator)?;
            let bytes = consensus::validated_bls_pubkey(bls_pubkey, bls_pop)?;
            if let Some(owner) = db.bls_pubkey_owner(&BlsPublicKey(bytes))?
                && &owner != validator
            {
                anyhow::bail!("BLS pubkey already registered to {owner}");
            }
            let existing_active = db
                .get_stake_allocation(&action.sender, validator)?
                .map(|a| a.active_amount)
                .unwrap_or(0);
            if existing_active + *stake < MIN_VALIDATOR_STAKE {
                anyhow::bail!(
                    "stake {stake} is below the minimum validator stake {MIN_VALIDATOR_STAKE}"
                );
            }
        }
        ActionPayload::LeaveValidator { validator } => {
            if !staking::is_authorized(&action.sender, validator, &operator_lookup)? {
                anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
            }
            let tip_height = db.get_tip_height()?.unwrap_or(0);
            let validators = db.get_validator_set_at(tip_height)?;
            if !validators.contains_key(validator) {
                anyhow::bail!("{validator} is not a current validator");
            }
            if validators.len() <= 1 {
                anyhow::bail!("cannot remove the last validator, chain would stall forever");
            }
        }
        ActionPayload::RegisterBlsKey {
            validator,
            pubkey,
            pop,
        } => {
            if !staking::is_authorized(&action.sender, validator, &operator_lookup)? {
                anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
            }
            let bytes = consensus::validated_bls_pubkey(pubkey, pop)?;
            if let Some(owner) = db.bls_pubkey_owner(&BlsPublicKey(bytes))?
                && &owner != validator
            {
                anyhow::bail!("BLS pubkey already registered to {owner}");
            }
        }
        _ => {}
    }
    Ok(())
}

/// 0.001 ARX, in IUM (ARX's base unit — 1 ARX = 1_000_000_000 IUM) base
/// per-action fee. The full fee is `metering::action_fee_for(weight)` —
/// this plus a per-weight term — charged in `charge_action_fee` below and
/// paid out through `on_block_sealed`'s `fees_collected`.
pub const ACTION_FEE: u128 = 1_000_000;

pub fn dispatch<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    let mut updates = dispatch_inner(
        action,
        view,
        operator_lookup,
        operator_validators_lookup,
        validators,
        current_height,
        bls_pubkey_owner_lookup,
    )?;
    consume_nonce(action, view, &mut updates)?;
    charge_action_fee(action, view, &mut updates)?;
    Ok(updates)
}

/// Ensures the action consumed exactly one nonce. Circuits that already
/// checked and bumped it leave the sender's entry at `current + 1` and are
/// left alone; everything else is checked here and bumped, so no action can
/// be replayed and no action can be applied out of order.
fn consume_nonce<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    updates: &mut BlockUpdates,
) -> anyhow::Result<()> {
    let current = view
        .get(&AccountKey(&action.sender))?
        .map(|entry| entry.nonce)
        .unwrap_or(0);
    let mut entry = match updates.accounts.0.get(&action.sender) {
        Some(entry) => entry.clone(),
        None => view.get(&AccountKey(&action.sender))?.unwrap_or_default(),
    };
    if entry.nonce != current {
        return Ok(());
    }
    if action.nonce != current {
        anyhow::bail!(
            "invalid nonce for {}: expected {current}, got {}",
            action.sender,
            action.nonce
        );
    }
    entry.nonce = current + 1;
    updates.accounts.0.insert(action.sender.clone(), entry);
    Ok(())
}

/// Debits the metered fee from `action.sender`'s balance on top of whatever
/// `dispatch_inner` already did. Reuses the sender's entry from `updates` if
/// the action already produced one (preserving whatever nonce/balance
/// change it made), otherwise fetches a fresh one via `view` so an action
/// that never touches its own sender's account (e.g. `RegisterBlsKey`)
/// still pays.
fn charge_action_fee<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    updates: &mut BlockUpdates,
) -> anyhow::Result<()> {
    let mut entry = match updates.accounts.0.get(&action.sender) {
        Some(entry) => entry.clone(),
        None => view.get(&AccountKey(&action.sender))?.ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no account to charge the action fee against",
                action.sender
            )
        })?,
    };
    let fee = metering::action_fee_for(metering::action_weight(action));
    entry.balance = entry
        .balance
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("insufficient balance for the action fee ({fee} IUM)"))?;
    updates.accounts.0.insert(action.sender.clone(), entry);
    Ok(())
}

fn dispatch_inner<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => account::transfer(view, action, to, *amount),
        ActionPayload::JoinValidator {
            validator,
            stake,
            bls_pubkey,
            bls_pop,
        } => staking::join_validator(
            action,
            view,
            validator,
            *stake,
            bls_pubkey,
            bls_pop,
            operator_lookup,
            bls_pubkey_owner_lookup,
            current_height,
        ),
        ActionPayload::LeaveValidator { validator } => staking::leave_validator(
            action,
            view,
            validator,
            operator_lookup,
            validators,
            current_height,
        ),
        ActionPayload::Stake { validator, amount } => {
            staking::stake(view, action, validator, *amount, current_height)
        }
        ActionPayload::Unstake { validator, amount } => {
            staking::unstake(view, action, validator, *amount, current_height)
        }
        ActionPayload::SubmitEquivocationEvidence { block_a, block_b } => {
            consensus::submit_equivocation_evidence(view, block_a, block_b, current_height)
        }
        ActionPayload::RegisterBlsKey {
            validator,
            pubkey,
            pop,
        } => consensus::register_bls_key(
            action,
            view,
            validator,
            pubkey,
            pop,
            current_height,
            operator_lookup,
            bls_pubkey_owner_lookup,
        ),
        ActionPayload::VerifyIdentityCredential { proof } => {
            identity::verify_identity_credential(view, action, proof)
        }
        ActionPayload::AuthorizeOperator { operator } => account::authorize_operator(
            action,
            operator,
            operator_lookup,
            operator_validators_lookup,
        ),
        ActionPayload::RevokeOperator => {
            account::revoke_operator(action, operator_lookup, operator_validators_lookup)
        }
        ActionPayload::GrantAttestation {
            subject,
            hash,
            topics,
            jurisdiction,
        } => identity::grant_attestation(
            view,
            action,
            subject,
            hash,
            topics,
            jurisdiction.as_deref(),
            current_height,
        ),
        ActionPayload::RevokeAttestation { subject } => {
            identity::revoke_attestation(view, action, subject)
        }
        ActionPayload::RegisterAsset {
            asset_id,
            compliance_required,
            metadata,
        } => asset::register_asset(
            view,
            action,
            asset_id,
            *compliance_required,
            metadata,
            current_height,
        ),
        ActionPayload::IssueAsset { asset, amount } => {
            asset::issue_asset(view, action, asset, *amount)
        }
        ActionPayload::RegisterAttestor {
            attestor,
            name,
            reason,
        } => identity::register_attestor(view, action, attestor, name, reason, current_height),
        ActionPayload::DeregisterAttestor { attestor, reason } => {
            identity::deregister_attestor(view, action, attestor, reason)
        }
        ActionPayload::FreezeAsset { asset, reason } => {
            asset::set_frozen(view, action, asset, true, reason)
        }
        ActionPayload::UnfreezeAsset { asset, reason } => {
            asset::set_frozen(view, action, asset, false, reason)
        }
        ActionPayload::ForcedTransfer {
            asset,
            from,
            to,
            amount,
            reason,
        } => asset::forced_transfer(view, action, asset, from, to, *amount, reason),
        ActionPayload::BurnAsset { asset, amount } => {
            asset::burn_asset(view, action, asset, *amount)
        }
        ActionPayload::LockIssuance { asset } => asset::lock_issuance(view, action, asset),
        ActionPayload::TransferIssuer { asset, new_issuer } => {
            asset::transfer_issuer(view, action, asset, new_issuer)
        }
        ActionPayload::SetAssetMetadataUri {
            asset,
            metadata_uri,
        } => asset::set_metadata_uri(view, action, asset, metadata_uri.clone()),
        ActionPayload::SetHolderFrozen {
            asset,
            holder,
            frozen,
        } => asset::set_holder_frozen(view, action, asset, holder, *frozen),
        ActionPayload::LockHolderAmount {
            asset,
            holder,
            amount,
        } => asset::lock_holder_amount(
            view,
            action,
            asset,
            holder,
            *amount,
            true,
            None,
            current_height,
        ),
        ActionPayload::LockHolderAmountUntil {
            asset,
            holder,
            amount,
            until_height,
        } => asset::lock_holder_amount(
            view,
            action,
            asset,
            holder,
            *amount,
            true,
            Some(*until_height),
            current_height,
        ),
        ActionPayload::SetAssetLimits {
            asset,
            max_holders,
            max_balance_per_holder,
            max_attestation_age,
        } => asset::set_limits(
            view,
            action,
            asset,
            *max_holders,
            *max_balance_per_holder,
            *max_attestation_age,
        ),
        ActionPayload::UnlockHolderAmount {
            asset,
            holder,
            amount,
        } => asset::lock_holder_amount(
            view,
            action,
            asset,
            holder,
            *amount,
            false,
            None,
            current_height,
        ),
        ActionPayload::IssuerForcedTransfer {
            asset,
            from,
            to,
            amount,
            reason,
        } => asset::issuer_forced_transfer(view, action, asset, from, to, *amount, reason),
        ActionPayload::RecoverHolder {
            asset,
            lost,
            replacement,
        } => asset::recover_holder(view, action, asset, lost, replacement, current_height),
        ActionPayload::IssueAssetTo { asset, to, amount } => {
            asset::issue_asset_to(view, action, asset, to, *amount, current_height)
        }
        ActionPayload::TransferAsset { asset, to, amount } => {
            asset::transfer_asset(view, action, asset, to, *amount, current_height)
        }
        ActionPayload::SubmitExecutionFault { artifact_json } => consensus::submit_execution_fault(
            view,
            artifact_json,
            current_height,
            bls_pubkey_owner_lookup,
        ),
    }
}

/// Shared test fixtures used by every handler module's `#[cfg(test)]` block
/// via `crate::test_support::*` — kept in one place so each split-out module
/// doesn't duplicate the same closures and builders.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;
    use xc_bls::BlsPublicKey;
    use xc_circuit::{AccountKey, StakeKey};
    use xc_primitives::{AccountEntry, Address, StakeAllocation};
    use xc_storage::{ArxiumDb, BlockView, StorageError};

    pub(crate) fn temp_db() -> ArxiumDb {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-payload-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        ArxiumDb::open(&dir).expect("open test db")
    }

    /// Builds a `BlockView` pre-populated via `put` so tests never touch
    /// `db` for real — same shape the closure-based mocks used to provide,
    /// just behind `KvRead` instead of `&dyn Fn`.
    pub(crate) fn seeded_view<'a>(
        db: &'a ArxiumDb,
        accounts: HashMap<Address, AccountEntry>,
        stakes: HashMap<(Address, Address), StakeAllocation>,
    ) -> BlockView<'a> {
        let mut view = BlockView::new(db);
        for (addr, entry) in accounts {
            view.put(&AccountKey(&addr), &entry).unwrap();
        }
        for ((master, validator), allocation) in stakes {
            view.put(
                &StakeKey {
                    master: &master,
                    validator: &validator,
                },
                &allocation,
            )
            .unwrap();
        }
        view
    }

    pub(crate) fn operator_lookup(_validator: &Address) -> Result<Option<Address>, StorageError> {
        Ok(None)
    }

    pub(crate) fn operator_validators_lookup(
        _operator: &Address,
    ) -> Result<Vec<Address>, StorageError> {
        Ok(Vec::new())
    }

    pub(crate) fn no_bls_owner(_pubkey: &BlsPublicKey) -> Result<Option<Address>, StorageError> {
        Ok(None)
    }

    pub(crate) fn make_operator_lookup(
        authorizations: HashMap<Address, Address>,
    ) -> impl Fn(&Address) -> Result<Option<Address>, StorageError> {
        move |validator| Ok(authorizations.get(validator).cloned())
    }

    /// Enough to pay any single action's metered fee — what tests fund
    /// "one action's worth" with, since the real fee depends on the variant
    /// and size. Exact post-fee balances use `fee_of`.
    pub(crate) const FEE_BUDGET: u128 = crate::ACTION_FEE + 1_000_000 * crate::metering::WEIGHT_FEE;

    pub(crate) fn fee_of(action: &crate::ChainAction) -> u128 {
        crate::metering::action_fee_for(crate::metering::action_weight(action))
    }

    pub(crate) fn funded(balance: u128) -> AccountEntry {
        AccountEntry {
            balance,
            ..Default::default()
        }
    }

    pub(crate) fn self_allocation(addr: &Address, active_amount: u128) -> StakeAllocation {
        StakeAllocation {
            master: addr.clone(),
            validator: addr.clone(),
            active_amount,
            unbonding: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    /// A real, on-curve BLS pubkey. Arbitrary bytes will not do —
    /// `validated_bls_pubkey` runs `blst`'s `validate()`, which is the point.
    pub(crate) fn test_bls_pubkey(seed: u8) -> Vec<u8> {
        let (_sk, pk) = xc_bls::keygen_from_seed(&[seed; 32]).expect("keygen");
        pk.0.to_vec()
    }

    /// The matching proof of possession — also mandatory now, and also not
    /// forgeable from arbitrary bytes. Seeds must line up with
    /// `test_bls_pubkey`'s.
    pub(crate) fn test_bls_pop(seed: u8) -> Vec<u8> {
        let (sk, _pk) = xc_bls::keygen_from_seed(&[seed; 32]).expect("keygen");
        xc_bls::prove_possession(&sk).0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use test_support::*;
    use xc_runtime_api::ChainRuntime;
    use xc_storage::{AccountUpdates, BlsKeyRegistration, OperatorUpdates, ValidatorSetSnapshot};

    // admission_precheck runs against a real ArxiumDb (unlike the
    // view-based dispatch tests in the handler modules) since it's meant to
    // run at RPC/gossip admission time, before a block-execution context
    // exists.
    fn precheck_test_db(validators: &[Address]) -> ArxiumDb {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-admission-precheck-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let db = ArxiumDb::open(&dir).expect("open test db");
        let genesis: ChainBlock = xc_primitives::Block::genesis(0);
        db.write_batches(&[&genesis]).unwrap();
        db.write_batches(&[&ValidatorSetSnapshot::equal_power(0, validators)])
            .unwrap();
        db
    }

    #[test]
    fn admission_precheck_rejects_unauthorized_sender() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            bob.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
                bls_pop: test_bls_pop(1),
            },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(err.to_string().contains("is not authorized to manage"));
    }

    #[test]
    fn admission_precheck_rejects_below_minimum_stake() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            alice.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE - 1,
                bls_pubkey: test_bls_pubkey(1),
                bls_pop: test_bls_pop(1),
            },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(
            err.to_string()
                .contains("below the minimum validator stake")
        );
    }

    #[test]
    fn admission_precheck_rejects_leaving_the_last_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = precheck_test_db(std::slice::from_ref(&alice));
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            alice.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator { validator: alice },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(err.to_string().contains("last validator"));
    }

    #[test]
    fn admission_precheck_accepts_authorized_sufficient_join() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            alice.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
                bls_pop: test_bls_pop(1),
            },
        };

        admission_precheck(&action, &db).expect("self-join at the minimum stake should pass");
    }

    #[test]
    fn admission_precheck_rejects_join_with_a_pubkey_already_held_by_a_different_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        let (sk, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        db.write_batches(&[&BlsKeyRegistration {
            address: bob,
            pubkey,
            effective_height: 0,
            previous_pubkey: None,
        }])
        .unwrap();
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            alice.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: pubkey.0.to_vec(),
                bls_pop: xc_bls::prove_possession(&sk).0.to_vec(),
            },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn admission_precheck_accepts_authorized_operator_join() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        db.write_batches(&[&OperatorUpdates {
            authorization: std::collections::BTreeMap::from([(alice.clone(), Some(bob.clone()))]),
            operator_index: std::collections::BTreeMap::from([(bob.clone(), vec![alice.clone()])]),
        }])
        .unwrap();
        db.write_batches(&[&AccountUpdates(BTreeMap::from([(
            bob.clone(),
            funded(FEE_BUDGET),
        )]))])
        .unwrap();
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
                bls_pop: test_bls_pop(1),
            },
        };

        admission_precheck(&action, &db)
            .expect("operator authorized via AuthorizeOperator should be allowed to join");
    }

    #[test]
    fn locally_adjudicate_execution_fault_rejects_malformed_json() {
        assert_eq!(
            CoreChainRuntime::locally_adjudicate_execution_fault("not json"),
            None
        );
    }

    #[test]
    fn locally_adjudicate_execution_fault_has_no_path_for_equivocation() {
        // Equivocation is context-free (verify() alone names the culprit),
        // so this hook — which exists for the two replay-adjudicated fault
        // kinds — has nothing to do with it and returns `None`.
        let artifact = xc_artifact::EvidenceArtifact {
            artifact_version: xc_artifact::ARTIFACT_VERSION,
            genesis_hash: "0xgenesis".to_string(),
            fault: xc_artifact::Fault::Equivocation {
                proposer_pubkey: format!("0x{}", hex::encode([1u8; 32])),
                height: 1,
                blocks: [
                    xc_artifact::BlockAttestation {
                        header: xc_artifact::CanonicalHeader {
                            height: 1,
                            parent_hash: "0xp".to_string(),
                            timestamp: 0,
                            tx_root: format!("0x{}", hex::encode([0u8; 32])),
                            proposer: "arx1x".to_string(),
                            state_root: "0xa".to_string(),
                            round: 0,
                        },
                        signature: "0xsig".to_string(),
                    },
                    xc_artifact::BlockAttestation {
                        header: xc_artifact::CanonicalHeader {
                            height: 1,
                            parent_hash: "0xp".to_string(),
                            timestamp: 0,
                            tx_root: format!("0x{}", hex::encode([0u8; 32])),
                            proposer: "arx1x".to_string(),
                            state_root: "0xb".to_string(),
                            round: 0,
                        },
                        signature: "0xsig".to_string(),
                    },
                ],
            },
            human_readable: serde_json::json!({}),
        };
        let artifact_json = serde_json::to_string(&artifact).unwrap();
        assert_eq!(
            CoreChainRuntime::locally_adjudicate_execution_fault(&artifact_json),
            None
        );
    }
}

/// Signing-byte vectors shared with the mobile clients.
///
/// `ArxiumCodec` in the iOS app and `ArxiumCodec.kt` on Android reimplement
/// bincode's framing by hand — they cannot call this encoder — so the only
/// thing standing between a wallet and a silently rejected signature is a
/// vector produced here and pinned there. A signature over the wrong bytes
/// fails verification on the node, not on the device, so drift shows up as
/// "my transfer vanished" rather than as an error.
///
/// Same purpose as the cross-crate dissent signing-byte checks: pin the
/// encoding at the boundary where two implementations have to agree.
#[cfg(test)]
mod client_signing_vectors {
    use super::*;
    use xc_primitives::{AssetMetadata, AssetRef, ClaimTopic};

    const ALICE: &str = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";
    const BOB: &str = "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5";
    /// `AssetRef::derive(ALICE, "gold")` — the same constant
    /// `xc_primitives::asset_ref` pins, repeated here so a codec that gets
    /// the derivation wrong fails on the vector rather than on the chain.
    const ALICE_GOLD: &str = "arxasset1z8d4jt8yt0xtjm6lvk8umc9relegrwq4xu928eqxyjfcsnjuex6qe873qa";

    fn gold() -> AssetRef {
        let derived = AssetRef::derive(&Address::parse(ALICE).unwrap(), "gold").unwrap();
        assert_eq!(
            derived.to_string(),
            ALICE_GOLD,
            "the pinned ref constant drifted from the derivation"
        );
        derived
    }

    fn hex_signing_bytes(nonce: u64, payload: ActionPayload) -> String {
        let action = Action {
            sender: Address::parse(ALICE).expect("valid sender"),
            nonce,
            payload,
            signature: None,
        };
        hex::encode(action.signing_bytes())
    }

    /// `TransferAsset` is variant 14 — after `RegisterAsset` (12) and
    /// `IssueAsset` (13), which the wallet never builds. Its fields frame as
    /// `{asset, to, amount}`; `asset` is an `AssetRef`, which encodes exactly
    /// like an `Address` (one length-prefixed bech32 string), so the codec's
    /// address writer is reused as-is.
    #[test]
    fn transfer_asset_vector_matches_the_mobile_codecs() {
        assert_eq!(
            hex_signing_bytes(
                3,
                ActionPayload::TransferAsset {
                    asset: gold(),
                    to: Address::parse(BOB).expect("valid recipient"),
                    amount: 1_000_000,
                },
            ),
            TRANSFER_ASSET_VECTOR,
            "TransferAsset signing bytes changed — the mobile codecs pin this \
             exact string and will sign rejected transactions until updated"
        );
    }

    /// `RegisterAsset` is variant 12 and the one asset variant that still
    /// carries the slug (`asset_id: String`) rather than a ref. This vector
    /// takes every branch of `AssetMetadata` that a hand-written encoder can
    /// get wrong: a non-empty `required_claims`, `Some` jurisdictions, a
    /// `max_supply` past the single-byte varint range (so the `0xfc` u32
    /// marker appears), a `Some` URI, and the two trailing display strings
    /// `symbol`/`name`, which come *after* `metadata_uri`.
    #[test]
    fn register_asset_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                0,
                ActionPayload::RegisterAsset {
                    asset_id: "gold".to_string(),
                    compliance_required: true,
                    metadata: AssetMetadata {
                        asset_class: xc_primitives::AssetClass::Bond,
                        decimals: 6,
                        required_claims: vec![ClaimTopic::Kyc, ClaimTopic::Accredited],
                        allowed_jurisdictions: Some(vec!["CH".to_string(), "DE".to_string()]),
                        max_supply: Some(1_000_000),
                        metadata_uri: Some("ipfs://a".to_string()),
                        symbol: "GOLD".to_string(),
                        name: "Gold".to_string(),
                    },
                },
            ),
            REGISTER_ASSET_VECTOR,
            "RegisterAsset signing bytes changed — the Console and Arx-Plus-Api \
             codecs pin this exact string"
        );
    }

    /// Every optional absent: `None` is one zero byte, not an empty
    /// collection — the difference between "unrestricted" and "nobody may
    /// hold it" — and `required_claims: []` is a zero-length vec. `symbol`
    /// and `name` are still present (they are mandatory on the chain).
    #[test]
    fn register_asset_default_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                0,
                ActionPayload::RegisterAsset {
                    asset_id: "gold".to_string(),
                    compliance_required: false,
                    metadata: AssetMetadata {
                        symbol: "GOLD".to_string(),
                        name: "Gold".to_string(),
                        ..AssetMetadata::default()
                    },
                },
            ),
            REGISTER_ASSET_DEFAULT_VECTOR,
            "RegisterAsset (default metadata) signing bytes changed — the Console \
             and Arx-Plus-Api codecs pin this exact string"
        );
    }

    /// `IssueAsset` is variant 13; nonce 1 because the client issues right
    /// after registering at nonce 0. `1000` lands in the `0xfb` u16 range.
    #[test]
    fn issue_asset_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                1,
                ActionPayload::IssueAsset {
                    asset: gold(),
                    amount: 1000
                }
            ),
            ISSUE_ASSET_VECTOR,
            "IssueAsset signing bytes changed — the Console and Arx-Plus-Api \
             codecs pin this exact string"
        );
    }

    /// Variants 18–20 (freeze, unfreeze, recovery-admin forced transfer), nonce 2.
    #[test]
    fn freeze_and_forced_transfer_vectors_match_the_client_codecs() {
        let bob = Address::parse(BOB).expect("valid");
        let alice = Address::parse(ALICE).expect("valid");
        let cases: [(&str, ActionPayload, &str); 3] = [
            (
                "FreezeAsset",
                ActionPayload::FreezeAsset {
                    asset: gold(),
                    reason: "court".into(),
                },
                FREEZE_ASSET_VECTOR,
            ),
            (
                "UnfreezeAsset",
                ActionPayload::UnfreezeAsset {
                    asset: gold(),
                    reason: "court".into(),
                },
                UNFREEZE_ASSET_VECTOR,
            ),
            (
                "ForcedTransfer",
                ActionPayload::ForcedTransfer {
                    asset: gold(),
                    from: bob,
                    to: alice,
                    amount: 1000,
                    reason: "court".into(),
                },
                FORCED_TRANSFER_VECTOR,
            ),
        ];
        for (name, payload, expected) in cases {
            assert_eq!(
                hex_signing_bytes(2, payload),
                expected,
                "{name} signing bytes changed — the client codecs pin this exact string"
            );
        }
    }

    /// Variants 21–26, one vector each so a codec that gets any index or
    /// field order wrong fails here rather than on the chain. Nonce 2 for all
    /// of them; `holder`/`from`/`lost` is BOB.
    #[test]
    fn holder_control_vectors_match_the_client_codecs() {
        let bob = Address::parse(BOB).expect("valid");
        let alice = Address::parse(ALICE).expect("valid");
        let cases: [(&str, ActionPayload, &str); 6] = [
            (
                "BurnAsset",
                ActionPayload::BurnAsset {
                    asset: gold(),
                    amount: 1000,
                },
                BURN_ASSET_VECTOR,
            ),
            (
                "SetHolderFrozen",
                ActionPayload::SetHolderFrozen {
                    asset: gold(),
                    holder: bob.clone(),
                    frozen: true,
                },
                SET_HOLDER_FROZEN_VECTOR,
            ),
            (
                "LockHolderAmount",
                ActionPayload::LockHolderAmount {
                    asset: gold(),
                    holder: bob.clone(),
                    amount: 1000,
                },
                LOCK_HOLDER_AMOUNT_VECTOR,
            ),
            (
                "UnlockHolderAmount",
                ActionPayload::UnlockHolderAmount {
                    asset: gold(),
                    holder: bob.clone(),
                    amount: 1000,
                },
                UNLOCK_HOLDER_AMOUNT_VECTOR,
            ),
            (
                "IssuerForcedTransfer",
                ActionPayload::IssuerForcedTransfer {
                    asset: gold(),
                    from: bob.clone(),
                    to: alice.clone(),
                    amount: 1000,
                    reason: "court".into(),
                },
                ISSUER_FORCED_TRANSFER_VECTOR,
            ),
            (
                "RecoverHolder",
                ActionPayload::RecoverHolder {
                    asset: gold(),
                    lost: bob,
                    replacement: alice,
                },
                RECOVER_HOLDER_VECTOR,
            ),
        ];
        for (name, payload, expected) in cases {
            assert_eq!(
                hex_signing_bytes(2, payload),
                expected,
                "{name} signing bytes changed — the client codecs pin this exact string"
            );
        }
    }

    /// Variant 28, nonce 2.
    #[test]
    fn lock_issuance_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(2, ActionPayload::LockIssuance { asset: gold() }),
            LOCK_ISSUANCE_VECTOR,
            "LockIssuance signing bytes changed — the client codecs pin this exact string"
        );
    }

    /// Variants 29 and 30, nonce 2.
    #[test]
    fn transfer_issuer_and_metadata_uri_vectors_match_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                2,
                ActionPayload::TransferIssuer {
                    asset: gold(),
                    new_issuer: Address::parse(BOB).expect("valid")
                }
            ),
            TRANSFER_ISSUER_VECTOR,
            "TransferIssuer signing bytes changed — the client codecs pin this exact string"
        );
        assert_eq!(
            hex_signing_bytes(
                2,
                ActionPayload::SetAssetMetadataUri {
                    asset: gold(),
                    metadata_uri: Some("ipfs://terms".into())
                }
            ),
            SET_ASSET_METADATA_URI_VECTOR,
            "SetAssetMetadataUri signing bytes changed — the client codecs pin this exact string"
        );
    }

    /// Variant 27, nonce 2, recipient BOB.
    #[test]
    fn issue_asset_to_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                2,
                ActionPayload::IssueAssetTo {
                    asset: gold(),
                    to: Address::parse(BOB).expect("valid"),
                    amount: 1000
                }
            ),
            ISSUE_ASSET_TO_VECTOR,
            "IssueAssetTo signing bytes changed — the client codecs pin this exact string"
        );
    }

    // Kept as constants so the values are greppable from the app repos.
    const TRANSFER_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a030e436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fc40420f00";
    const REGISTER_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a000c04676f6c64010306020002010202434802444501fc40420f000108697066733a2f2f6104474f4c4404476f6c64";
    const REGISTER_ASSET_DEFAULT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a000c04676f6c640000000000000004474f4c4404476f6c64";
    const ISSUE_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a010d436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a7565783671653837337161fbe803";
    const FREEZE_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0212436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a756578367165383733716105636f757274";
    const UNFREEZE_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0213436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a756578367165383733716105636f757274";
    const FORCED_TRANSFER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0214436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b353e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737afbe80305636f757274";
    const BURN_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0215436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a7565783671653837337161fbe803";
    const SET_HOLDER_FROZEN_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0216436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b3501";
    const LOCK_HOLDER_AMOUNT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0217436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fbe803";
    const UNLOCK_HOLDER_AMOUNT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0218436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fbe803";
    const ISSUER_FORCED_TRANSFER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a0219436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b353e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737afbe80305636f757274";
    const RECOVER_HOLDER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021a436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b353e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a";
    const LOCK_ISSUANCE_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021c436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a7565783671653837337161";
    const TRANSFER_ISSUER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021d436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35";
    const SET_ASSET_METADATA_URI_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021e436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a7565783671653837337161010c697066733a2f2f7465726d73";
    const ISSUE_ASSET_TO_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021b436172786173736574317a3864346a743879743078746a6d366c766b38756d633972656c6567727771347875393238657178796a6663736e6a75657836716538373371613e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fbe803";
}
