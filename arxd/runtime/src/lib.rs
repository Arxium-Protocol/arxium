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
mod identity;
mod pair;
mod specs;
mod staking;

pub use staking::MIN_VALIDATOR_STAKE;

use serde::{Deserialize, Serialize};
use xc_bls::BlsPublicKey;
use xc_chain_spec::presets::PresetRegistry;
use xc_circuit::{AccountKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address, AssetMetadata, ClaimTopic, CountryCode};
use xc_storage::{ArxiumDb, BlockView, StorageError};

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer {
        to: Address,
        amount: u128,
    },
    /// Staking to join the validator set: routed through
    /// `circuit_staking::apply_stake` with `master == sender`, so it's held
    /// in the same `stake_subaccount` mechanism regular delegators use —
    /// same balance check, same "already controlled by another master"
    /// rejection, no new bookkeeping. Takes effect one block after this
    /// action lands (`xc_executor::accept_block`'s effective-height rule) —
    /// can't vote itself into this block's own proposer slot. `stake` on
    /// `ValidatorEntry` is informational only; `ValidatorSetSnapshot` never
    /// persists it, so the `StakeAllocation` for `(sender, validator)` is the
    /// real source of truth for how much a validator has at stake.
    ///
    /// `sender == validator` for ordinary self-service joining. `sender !=
    /// validator` is a *delegated* join — `sender` must be `validator`'s
    /// authorized operator (see `AuthorizeOperator`), and `sender`'s own
    /// balance funds the stake, same as a third-party `Stake` action. That
    /// also means `sender` becomes `validator`'s stake master going forward
    /// (`circuit_staking::apply_stake`'s single-master invariant) — the
    /// validator can't separately self-stake later while a delegated master
    /// holds that slot.
    JoinValidator {
        validator: Address,
        stake: u128,
        /// The validator's BLS finality key, registered atomically with the
        /// join. Required, not optional: a validator without one is counted
        /// toward the finality quorum while being unable to vote, so every
        /// such validator raises the threshold and contributes nothing to
        /// meeting it. Enough of them and the chain produces blocks forever
        /// while finalizing nothing, with no symptom but a warning per
        /// dropped vote.
        ///
        /// Carried in the action rather than required as a prior
        /// `RegisterBlsKey` so joining is atomic and cannot half-succeed —
        /// this is Cosmos's `MsgCreateValidator.pubkey`. `RegisterBlsKey`
        /// remains, for rotating a key on an existing validator.
        bls_pubkey: Vec<u8>,
        /// Proof of possession for `bls_pubkey` — `xc_bls::prove_possession`,
        /// printed alongside the key by `arxd keys`. Without it a rogue key
        /// forges quorum certificates; see `consensus::validated_bls_pubkey`.
        bls_pop: Vec<u8>,
    },
    /// Removal from the validator set, routed through
    /// `circuit_staking::apply_unstake` for `validator`'s full self-stake
    /// before the `ValidatorChange::Leave` is allowed. Leaving drops the
    /// validator from the proposer rotation immediately, but the stake sits
    /// in `Unbonding` for `circuit_staking::UNBONDING_BLOCKS` — and stays
    /// slashable that whole time (`circuit_staking::apply_slash` treats
    /// unbonding funds as fair game). Rejected if `validator` isn't
    /// currently a validator, or if they're the last one — an empty
    /// validator set means `expected_proposer` returns `None` forever and
    /// the chain can never produce another block (the same deadlock hit live
    /// this session from running `--bootnode` on two machines,
    /// self-inflicted here instead).
    ///
    /// `sender == validator` for self-service leaving. `sender != validator`
    /// is delegated — same authorization rule as `JoinValidator` — and the
    /// unstaked funds return to whoever `validator`'s recorded master is
    /// (`sender` in the self-service case, the authorized operator in the
    /// delegated case), never anywhere else.
    LeaveValidator {
        validator: Address,
    },
    /// MW-signature-only stake into a validator's sub-account
    /// (`circuit_staking::stake_subaccount`). See `circuit_staking::apply_stake`.
    Stake {
        validator: Address,
        amount: u128,
    },
    /// MW-signature-only partial or full unstake, subject to
    /// `circuit_staking::UNBONDING_BLOCKS`. See `circuit_staking::apply_unstake`.
    /// There is deliberately no `Slash` variant here — slashing is never
    /// user-submitted, so it's unreachable from RPC/mempool by construction
    /// (see `circuit_staking::apply_slash`).
    Unstake {
        validator: Address,
        amount: u128,
    },
    /// Proof that a validator signed two different blocks at the same
    /// height — normally built and submitted by `xc_evidence::spawn_evidence_watcher`
    /// when it observes a competing block, never hand-crafted by an
    /// ordinary user. Anyone *could* submit one given the two blocks, but
    /// `xc_evidence::verify_equivocation` is what actually gates the slash, not
    /// who submitted it — so that's fine.
    SubmitEquivocationEvidence {
        block_a: Box<ChainBlock>,
        block_b: Box<ChainBlock>,
    },
    /// Registers `validator`'s BLS pubkey for finality-certificate
    /// precommit voting (`arxd/finality`). Any address may be registered —
    /// the key is only meaningful once/if that address is also in the
    /// validator set at some height; no membership check happens here.
    /// `sender == validator` for self-registration; `sender != validator` is
    /// delegated, same authorization rule as `JoinValidator`. This lets a
    /// validator's operator register the key on its behalf without the
    /// validator's own key ever leaving the machine it was generated on
    /// (`arxd bls-key`).
    RegisterBlsKey {
        validator: Address,
        pubkey: Vec<u8>,
        /// Proof of possession for `pubkey` — see `JoinValidator::bls_pop`.
        pop: Vec<u8>,
    },
    /// A Groth16 proof of knowledge of a preimage hashing (via
    /// `circuit_identity_zk`'s Poseidon circuit) to the sender's existing
    /// `AccountEntry.identity_hash`. Verified against the checked-in devnet
    /// verifying key — see `circuits/identity-zk`'s module docs for why
    /// that key isn't from a real trusted-setup ceremony. On success, marks
    /// `zk_identity_verified` on the sender's account.
    VerifyIdentityCredential {
        proof: Vec<u8>,
    },
    /// Grants `operator` authority to submit `JoinValidator`/
    /// `LeaveValidator`/`RegisterBlsKey` on the sender's behalf — self-signed
    /// only, this is how a validator opts in to delegated management, never
    /// something an operator can grant itself. Overwrites any previously
    /// authorized operator (at most one at a time, mirroring
    /// `circuit_staking::apply_stake`'s single-master invariant).
    ///
    /// Appended here rather than inserted among the existing variants —
    /// `ActionPayload`'s wire format (bincode, used for gossip/sync, and
    /// hand-mirrored by out-of-process codecs like Arx-Plus's Swift one)
    /// encodes enum variants by discriminant index, so inserting earlier
    /// would silently shift every later variant's index.
    AuthorizeOperator {
        operator: Address,
    },
    /// Revokes the sender's currently authorized operator, if any —
    /// self-signed only, so a validator can always unilaterally cut off a
    /// compromised or unwanted operator regardless of what that operator
    /// does or doesn't do.
    RevokeOperator,
    /// Marks `subject` eligible (sets `AccountEntry.identity_hash`) — only
    /// a registered attestor (membership in `CF_ATTESTORS`, managed via
    /// `RegisterAttestor`/`DeregisterAttestor`) may submit this. Records
    /// `sender` in `AccountEntry.attested_by` for accountability.
    GrantAttestation {
        subject: Address,
        hash: String,
        /// Which claim topics this attestation confers. Empty grants an
        /// `identity_hash` and nothing topic-level, which is what every
        /// attestation did before topics existed and is still enough for
        /// assets that gate on `compliance_required`.
        topics: Vec<ClaimTopic>,
        /// Subject's jurisdiction, for assets restricting
        /// `allowed_jurisdictions`. `None` leaves it unknown, and an asset
        /// with a restriction rejects unknown rather than permitting it.
        jurisdiction: Option<CountryCode>,
    },
    /// Reverses `GrantAttestation` — clears `identity_hash` and, since a
    /// revoked KYC status shouldn't leave a stale ZK-verified flag around,
    /// also clears `zk_identity_verified`. Any registered attestor may
    /// revoke any attestation (permissive revocation), not just the one
    /// that granted it.
    RevokeAttestation {
        subject: Address,
    },
    /// Registers a new regulated asset, `sender` becoming its issuer.
    /// Rejected if `asset_id` is already registered, or if `asset_id` /
    /// `metadata` fail `asset::register_asset`'s validation.
    ///
    /// `metadata` was added to this variant in place rather than as a new
    /// variant: bincode encodes struct-variant fields positionally, so this
    /// changes the encoding and old blocks carrying the two-field form no
    /// longer decode. That is acceptable only because devnet genesis is being
    /// reset alongside it — on a live chain this would need a new variant
    /// appended instead. Retracer's hand-mirrored copy of this enum
    /// (`crates/ingestion/src/corechain_payload.rs`) must gain the same
    /// field, in this position, in the same release.
    RegisterAsset {
        asset_id: String,
        compliance_required: bool,
        metadata: AssetMetadata,
    },
    /// Mints `amount` of `asset_id` into the issuer's own asset balance —
    /// only the registered issuer may call this. Native balance untouched.
    IssueAsset {
        asset_id: String,
        amount: u128,
    },
    /// Compliance-gated transfer of a registered asset — distinct from
    /// `Transfer`, which only ever moves the native token and is never
    /// KYC-gated.
    TransferAsset {
        asset_id: String,
        to: Address,
        amount: u128,
    },
    /// Adds `attestor` to the trusted-attestor set (`identity::GovernorKey`
    /// only, see `Snapshot.governor`) — the Trust Spectrum's multi-attestor
    /// model: more than one regulated KYC provider can hold
    /// `GrantAttestation`/`RevokeAttestation` rights at once. Rejected if
    /// `attestor` is already registered.
    RegisterAttestor {
        attestor: Address,
        name: String,
    },
    /// Removes `attestor` from the trusted-attestor set (`GovernorKey`
    /// only). Any registered attestor may still revoke attestations that
    /// `attestor` previously granted — see `identity::require_attestor`.
    DeregisterAttestor {
        attestor: Address,
    },
    /// Submits a `Fault::ActionDivergence`/`Fault::BlockDivergence` evidence
    /// artifact (JSON-serialized `xc_artifact::EvidenceArtifact`) for
    /// on-chain adjudication and slashing — the counterpart to
    /// `SubmitEquivocationEvidence` for the two fault kinds that need
    /// chain-specific replay (see `adjudicate`) rather than a
    /// context-free signature/proof check to name a culprit. Anyone may
    /// submit one, same as equivocation evidence — `adjudicate::*` and the
    /// artifact's own signatures are what gate the slash, not who
    /// submitted it.
    SubmitExecutionFault {
        artifact_json: String,
    },
    /// Halts all transfers of `asset_id` until an `UnfreezeAsset` lands.
    /// Issuance is deliberately unaffected — a freeze is about circulation,
    /// not about sealing the supply.
    ///
    /// Appended here, not inserted: see `AuthorizeOperator` above for why
    /// variant order is part of the wire format. Retracer keeps a
    /// hand-mirrored copy of this enum
    /// (`crates/ingestion/src/corechain_payload.rs`) that has to gain the
    /// same variants in the same order, or it will misdecode blocks rather
    /// than fail on them.
    FreezeAsset {
        asset_id: String,
    },
    /// Lifts a `FreezeAsset`. Idempotent — unfreezing an asset that isn't
    /// frozen succeeds rather than erroring, so a governor never has to know
    /// the current flag to reach the state they want.
    UnfreezeAsset {
        asset_id: String,
    },
    /// Moves `amount` of `asset_id` from `from` to `to` without `from`'s
    /// signature and without any compliance, claim, jurisdiction or freeze
    /// check — the chain governor only. This is the recovery and enforcement
    /// path for what compliance cannot express: a court-ordered
    /// reassignment, a sanctioned holder, a holder who has lost their key.
    /// It still cannot mint: `from` must actually hold the balance.
    ///
    /// `reason` is mandatory and non-empty. It is not stored in state — it
    /// lives in the block that carried the action, which is the durable,
    /// replicated audit record a regulator would be shown, and keeping it out
    /// of state avoids growing the trie with free-text an issuer controls.
    ///
    /// Appended, like `FreezeAsset`/`UnfreezeAsset` above; the same note
    /// about Retracer's mirrored enum applies.
    ForcedTransfer {
        asset_id: String,
        from: Address,
        to: Address,
        amount: u128,
        reason: String,
    },
    /// Issuer destroys `amount` of its own balance; `total_supply` follows.
    /// Variant 21 — appended, so Retracer's mirror and the client codecs must
    /// add it in this position.
    BurnAsset {
        asset_id: String,
        amount: u128,
    },
    /// Issuer takes a holder out of circulation for one asset (or back in) —
    /// T-REX `setAddressFrozen`. Variant 22.
    SetHolderFrozen {
        asset_id: String,
        holder: Address,
        frozen: bool,
    },
    /// Issuer locks `amount` of a holder's balance against compliant
    /// transfers — T-REX `freezePartialTokens`. Variant 23.
    LockHolderAmount {
        asset_id: String,
        holder: Address,
        amount: u128,
    },
    /// Reverses `LockHolderAmount`. Variant 24.
    UnlockHolderAmount {
        asset_id: String,
        holder: Address,
        amount: u128,
    },
    /// The issuer's own forced transfer — T-REX `forcedTransfer` by an
    /// agent — scoped to assets it issued, same audited `reason` as the
    /// governor's `ForcedTransfer`. Variant 25.
    IssuerForcedTransfer {
        asset_id: String,
        from: Address,
        to: Address,
        amount: u128,
        reason: String,
    },
    /// Move everything `lost` holds of an asset to `replacement`, which must
    /// pass the asset's compliance rules — T-REX `recoveryAddress`. Issuer
    /// only. Variant 26.
    RecoverHolder {
        asset_id: String,
        lost: Address,
        replacement: Address,
    },
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

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
            &|pk: &BlsPublicKey| ctx.db.bls_pubkey_owner(pk),
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
        let reward_updates = circuit_staking::apply_block_reward(view, proposer, fees_collected)?;
        let mut updates = BlockUpdates {
            accounts: reward_updates,
            ..Default::default()
        };
        if let Some(primary) = xc_primitives::expected_proposer(validators, height) {
            let (downtime_accounts, downtime_stakes) =
                circuit_staking::apply_downtime_slash(view, &primary, proposer, height)?;
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
    if balance < ACTION_FEE {
        anyhow::bail!("insufficient balance for the action fee ({ACTION_FEE} IUM)");
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
            if !validators.contains(validator) {
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

/// 0.001 ARX, in IUM (ARX's base unit — 1 ARX = 1_000_000_000 IUM) flat
/// per-action fee, burned (no recipient), not a fee market. Devnet stub
/// like `MIN_VALIDATOR_STAKE`; swapping it for a per-action-type fee or a
/// validator/treasury payout only means changing `charge_action_fee` below,
/// not any call site.
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
    consume_nonce(action, view, &mut updates, current_height)?;
    charge_action_fee(action, view, &mut updates)?;
    Ok(updates)
}

/// First height at which every action must carry — and advance — the
/// sender's nonce. Before it, only the circuits that moved a balance checked
/// the nonce (`account`, `staking`, `rwa-asset::apply_issue`/`transfer`), so
/// `RegisterAsset`, the freezes, attestations and key registrations were
/// applied at any nonce and never bumped it; devnet history up to here
/// contains such blocks, and re-executing them under the strict rule would
/// reject them. ponytail: a constant, not a chain-spec field — devnet is the
/// only chain and this is its one activation.
pub const NONCE_DISCIPLINE_HEIGHT: u64 = 64_000;

/// Ensures the action consumed exactly one nonce. Circuits that already
/// checked and bumped it leave the sender's entry at `current + 1` and are
/// left alone; everything else is checked here and bumped, so no action can
/// be replayed and no action can be applied out of order.
fn consume_nonce<V: KvRead<Error = StorageError>>(
    action: &ChainAction,
    view: &V,
    updates: &mut BlockUpdates,
    current_height: u64,
) -> anyhow::Result<()> {
    if current_height < NONCE_DISCIPLINE_HEIGHT {
        return Ok(());
    }
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
        anyhow::bail!("invalid nonce for {}: expected {current}, got {}", action.sender, action.nonce);
    }
    entry.nonce = current + 1;
    updates.accounts.0.insert(action.sender.clone(), entry);
    Ok(())
}

/// Debits `ACTION_FEE` from `action.sender`'s balance on top of whatever
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
    entry.balance = entry.balance.checked_sub(ACTION_FEE).ok_or_else(|| {
        anyhow::anyhow!("insufficient balance for the action fee ({ACTION_FEE} IUM)")
    })?;
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
        ActionPayload::IssueAsset { asset_id, amount } => {
            asset::issue_asset(view, action, asset_id, *amount)
        }
        ActionPayload::RegisterAttestor { attestor, name } => {
            identity::register_attestor(view, action, attestor, name, current_height)
        }
        ActionPayload::DeregisterAttestor { attestor } => {
            identity::deregister_attestor(view, action, attestor)
        }
        ActionPayload::FreezeAsset { asset_id } => asset::set_frozen(view, action, asset_id, true),
        ActionPayload::UnfreezeAsset { asset_id } => {
            asset::set_frozen(view, action, asset_id, false)
        }
        ActionPayload::ForcedTransfer {
            asset_id,
            from,
            to,
            amount,
            reason,
        } => asset::forced_transfer(view, action, asset_id, from, to, *amount, reason),
        ActionPayload::BurnAsset { asset_id, amount } => asset::burn_asset(view, action, asset_id, *amount),
        ActionPayload::SetHolderFrozen { asset_id, holder, frozen } => {
            asset::set_holder_frozen(view, action, asset_id, holder, *frozen)
        }
        ActionPayload::LockHolderAmount { asset_id, holder, amount } => {
            asset::lock_holder_amount(view, action, asset_id, holder, *amount, true)
        }
        ActionPayload::UnlockHolderAmount { asset_id, holder, amount } => {
            asset::lock_holder_amount(view, action, asset_id, holder, *amount, false)
        }
        ActionPayload::IssuerForcedTransfer { asset_id, from, to, amount, reason } => {
            asset::issuer_forced_transfer(view, action, asset_id, from, to, *amount, reason)
        }
        ActionPayload::RecoverHolder { asset_id, lost, replacement } => {
            asset::recover_holder(view, action, asset_id, lost, replacement)
        }
        ActionPayload::TransferAsset {
            asset_id,
            to,
            amount,
        } => asset::transfer_asset(view, action, asset_id, to, *amount),
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
        db.write_batches(&[&ValidatorSetSnapshot {
            effective_height: 0,
            validators: validators.to_vec(),
        }])
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
            funded(ACTION_FEE),
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
            funded(ACTION_FEE),
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
            funded(ACTION_FEE),
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
            funded(ACTION_FEE),
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
            funded(ACTION_FEE),
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
            funded(ACTION_FEE),
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

    const ALICE: &str = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";
    const BOB: &str = "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5";

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
    /// `{asset_id, to, amount}`, so the encoding is one more length-prefixed
    /// string than `Transfer` carries before the amount varint.
    #[test]
    fn transfer_asset_vector_matches_the_mobile_codecs() {
        assert_eq!(
            hex_signing_bytes(
                3,
                ActionPayload::TransferAsset {
                    asset_id: "gold".to_string(),
                    to: Address::parse(BOB).expect("valid recipient"),
                    amount: 1_000_000,
                },
            ),
            TRANSFER_ASSET_VECTOR,
            "TransferAsset signing bytes changed — the mobile codecs pin this \
             exact string and will sign rejected transactions until updated"
        );
    }

    /// Kept as a constant so the value is greppable from the app repos.
    const TRANSFER_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a030e04676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fc40420f00";

    /// `RegisterAsset` is variant 12. This vector takes every branch of
    /// `AssetMetadata` that a hand-written encoder can get wrong: a non-empty
    /// `required_claims`, `Some` jurisdictions, a `max_supply` past the
    /// single-byte varint range (so the `0xfc` u32 marker appears) and a
    /// `Some` URI. The payload bytes match the fixture pinned in
    /// Arx-Plus-Api's `TestCanonicalPayloadMatchesNodeEncoding`.
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
    /// hold it" — and `required_claims: []` is a zero-length vec.
    #[test]
    fn register_asset_default_vector_matches_the_client_codecs() {
        assert_eq!(
            hex_signing_bytes(
                0,
                ActionPayload::RegisterAsset {
                    asset_id: "gold".to_string(),
                    compliance_required: false,
                    metadata: AssetMetadata::default(),
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
                    asset_id: "gold".to_string(),
                    amount: 1000
                },
            ),
            ISSUE_ASSET_VECTOR,
            "IssueAsset signing bytes changed — the Console and Arx-Plus-Api \
             codecs pin this exact string"
        );
    }

    /// Variants 21–26, one vector each so a codec that gets any index or
    /// field order wrong fails here rather than on the chain. Nonce 2 for all
    /// of them; `holder`/`from`/`lost` is BOB.
    #[test]
    fn holder_control_vectors_match_the_client_codecs() {
        let bob = Address::parse(BOB).expect("valid");
        let alice = Address::parse(ALICE).expect("valid");
        let cases: [(&str, ActionPayload, &str); 6] = [
            ("BurnAsset", ActionPayload::BurnAsset { asset_id: "gold".into(), amount: 1000 }, BURN_ASSET_VECTOR),
            ("SetHolderFrozen", ActionPayload::SetHolderFrozen { asset_id: "gold".into(), holder: bob.clone(), frozen: true }, SET_HOLDER_FROZEN_VECTOR),
            ("LockHolderAmount", ActionPayload::LockHolderAmount { asset_id: "gold".into(), holder: bob.clone(), amount: 1000 }, LOCK_HOLDER_AMOUNT_VECTOR),
            ("UnlockHolderAmount", ActionPayload::UnlockHolderAmount { asset_id: "gold".into(), holder: bob.clone(), amount: 1000 }, UNLOCK_HOLDER_AMOUNT_VECTOR),
            ("IssuerForcedTransfer", ActionPayload::IssuerForcedTransfer { asset_id: "gold".into(), from: bob.clone(), to: alice.clone(), amount: 1000, reason: "court".into() }, ISSUER_FORCED_TRANSFER_VECTOR),
            ("RecoverHolder", ActionPayload::RecoverHolder { asset_id: "gold".into(), lost: bob, replacement: alice }, RECOVER_HOLDER_VECTOR),
        ];
        for (name, payload, expected) in cases {
            assert_eq!(hex_signing_bytes(2, payload), expected, "{name} signing bytes changed — the client codecs pin this exact string");
        }
    }

    const BURN_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021504676f6c64fbe803";
    const SET_HOLDER_FROZEN_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021604676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b3501";
    const LOCK_HOLDER_AMOUNT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021704676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fbe803";
    const UNLOCK_HOLDER_AMOUNT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021804676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b35fbe803";
    const ISSUER_FORCED_TRANSFER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021904676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b353e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737afbe80305636f757274";
    const RECOVER_HOLDER_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a021a04676f6c643e617278317379756877723467303574343734347232336e76786e7237656e39636d7a35336b6e687230676a6137633834687237666b7732717067686a6b353e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a";

    const REGISTER_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a000c04676f6c64010306020002010202434802444501fc40420f000108697066733a2f2f61";
    const REGISTER_ASSET_DEFAULT_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a000c04676f6c6400000000000000";
    const ISSUE_ASSET_VECTOR: &str = "3e61727831333279773868743570386365746c326a6d766b6e65776a6177743978777a646c726b327079786c6e776a797172647130646177716171366c737a010d04676f6c64fbe803";
}
