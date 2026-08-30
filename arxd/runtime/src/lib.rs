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
mod consensus;
mod identity;
mod specs;
mod staking;

pub use staking::MIN_VALIDATOR_STAKE;

use serde::{Deserialize, Serialize};
use xc_bls::BlsPublicKey;
use xc_chain_spec::presets::PresetRegistry;
use xc_circuit::{AccountKey, KvRead};
use xc_executor::BlockUpdates;
use xc_primitives::{Action, Address};
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
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

/// CoreChain's `ChainRuntime` implementation — see `runtime_api::ChainRuntime`
/// for what this makes `arxd/node` generic over.
pub struct CoreChainRuntime;

impl runtime_api::ChainRuntime for CoreChainRuntime {
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
        view: &BlockView<'_>,
        db: &ArxiumDb,
        operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
        operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
        validators: &[Address],
        current_height: u64,
    ) -> anyhow::Result<BlockUpdates> {
        dispatch(
            action,
            view,
            operator_lookup,
            operator_validators_lookup,
            validators,
            current_height,
            &|h, p| db.evidence_processed(h, p),
            &|pk: &BlsPublicKey| db.bls_pubkey_owner(pk),
        )
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
    let balance = db.get_account(&action.sender)?.map(|e| e.balance).unwrap_or(0);
    if balance < ACTION_FEE {
        anyhow::bail!("insufficient balance for the action fee ({ACTION_FEE} IUM)");
    }
    let operator_lookup = |validator: &Address| db.get_operator(validator);
    match &action.payload {
        ActionPayload::JoinValidator { validator, stake, bls_pubkey } => {
            if !staking::is_authorized(&action.sender, validator, &operator_lookup)? {
                anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
            }
            let bytes = consensus::validated_bls_pubkey(bls_pubkey)?;
            if let Some(owner) = db.bls_pubkey_owner(&BlsPublicKey(bytes))? {
                if &owner != validator {
                    anyhow::bail!("BLS pubkey already registered to {owner}");
                }
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
        ActionPayload::RegisterBlsKey { validator, pubkey } => {
            if !staking::is_authorized(&action.sender, validator, &operator_lookup)? {
                anyhow::bail!("{} is not authorized to manage {validator}", action.sender);
            }
            let bytes = consensus::validated_bls_pubkey(pubkey)?;
            if let Some(owner) = db.bls_pubkey_owner(&BlsPublicKey(bytes))? {
                if &owner != validator {
                    anyhow::bail!("BLS pubkey already registered to {owner}");
                }
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

pub fn dispatch(
    action: &ChainAction,
    view: &BlockView<'_>,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
    evidence_processed: &dyn Fn(u64, &Address) -> Result<bool, StorageError>,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    let mut updates = dispatch_inner(
        action,
        view,
        operator_lookup,
        operator_validators_lookup,
        validators,
        current_height,
        evidence_processed,
        bls_pubkey_owner_lookup,
    )?;
    charge_action_fee(action, view, &mut updates)?;
    Ok(updates)
}

/// Debits `ACTION_FEE` from `action.sender`'s balance on top of whatever
/// `dispatch_inner` already did. Reuses the sender's entry from `updates` if
/// the action already produced one (preserving whatever nonce/balance
/// change it made), otherwise fetches a fresh one via `view` so an action
/// that never touches its own sender's account (e.g. `RegisterBlsKey`)
/// still pays.
fn charge_action_fee(
    action: &ChainAction,
    view: &BlockView<'_>,
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

fn dispatch_inner(
    action: &ChainAction,
    view: &BlockView<'_>,
    operator_lookup: &dyn Fn(&Address) -> Result<Option<Address>, StorageError>,
    operator_validators_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
    evidence_processed: &dyn Fn(u64, &Address) -> Result<bool, StorageError>,
    bls_pubkey_owner_lookup: &dyn Fn(&BlsPublicKey) -> Result<Option<Address>, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => account::transfer(view, action, to, *amount),
        ActionPayload::JoinValidator { validator, stake, bls_pubkey } => staking::join_validator(
            action,
            view,
            validator,
            *stake,
            bls_pubkey,
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
            consensus::submit_equivocation_evidence(
                view,
                block_a,
                block_b,
                evidence_processed,
                current_height,
            )
        }
        ActionPayload::RegisterBlsKey { validator, pubkey } => consensus::register_bls_key(
            action,
            validator,
            pubkey,
            operator_lookup,
            bls_pubkey_owner_lookup,
        ),
        ActionPayload::VerifyIdentityCredential { proof } => {
            identity::verify_identity_credential(view, action, proof)
        }
        ActionPayload::AuthorizeOperator { operator } => {
            account::authorize_operator(action, operator, operator_lookup, operator_validators_lookup)
        }
        ActionPayload::RevokeOperator => {
            account::revoke_operator(action, operator_lookup, operator_validators_lookup)
        }
    }
}

/// Shared test fixtures used by every handler module's `#[cfg(test)]` block
/// via `crate::test_support::*` — kept in one place so each split-out module
/// doesn't duplicate the same closures and builders.
#[cfg(test)]
pub(crate) mod test_support {
    use xc_bls::BlsPublicKey;
    use xc_circuit::{AccountKey, StakeKey};
    use xc_primitives::{Address, AccountEntry, StakeAllocation};
    use xc_storage::{ArxiumDb, BlockView, StorageError};
    use std::collections::HashMap;

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
            view.put(&StakeKey { master: &master, validator: &validator }, &allocation)
                .unwrap();
        }
        view
    }

    pub(crate) fn operator_lookup(_validator: &Address) -> Result<Option<Address>, StorageError> {
        Ok(None)
    }

    pub(crate) fn operator_validators_lookup(_operator: &Address) -> Result<Vec<Address>, StorageError> {
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
            nonce: 0,
            identity_hash: None,
            zk_identity_verified: false,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::*;
    use std::collections::HashMap;
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
        db.write_batches(&[&AccountUpdates(HashMap::from([(bob.clone(), funded(ACTION_FEE))]))])
            .unwrap();
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(err.to_string().contains("is not authorized to manage"));
    }

    #[test]
    fn admission_precheck_rejects_below_minimum_stake() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        db.write_batches(&[&AccountUpdates(HashMap::from([(alice.clone(), funded(ACTION_FEE))]))])
            .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE - 1,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        let err = admission_precheck(&action, &db).unwrap_err();
        assert!(err.to_string().contains("below the minimum validator stake"));
    }

    #[test]
    fn admission_precheck_rejects_leaving_the_last_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = precheck_test_db(&[alice.clone()]);
        db.write_batches(&[&AccountUpdates(HashMap::from([(alice.clone(), funded(ACTION_FEE))]))])
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
        db.write_batches(&[&AccountUpdates(HashMap::from([(alice.clone(), funded(ACTION_FEE))]))])
            .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        admission_precheck(&action, &db).expect("self-join at the minimum stake should pass");
    }

    #[test]
    fn admission_precheck_rejects_join_with_a_pubkey_already_held_by_a_different_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let db = precheck_test_db(&[]);
        let (_, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        db.write_batches(&[&BlsKeyRegistration { address: bob, pubkey }]).unwrap();
        db.write_batches(&[&AccountUpdates(HashMap::from([(alice.clone(), funded(ACTION_FEE))]))])
            .unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: pubkey.0.to_vec(),
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
        db.write_batches(&[&AccountUpdates(HashMap::from([(bob.clone(), funded(ACTION_FEE))]))])
            .unwrap();
        let action = Action {
            sender: bob,
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                validator: alice,
                stake: MIN_VALIDATOR_STAKE,
                bls_pubkey: test_bls_pubkey(1),
            },
        };

        admission_precheck(&action, &db)
            .expect("operator authorized via AuthorizeOperator should be allowed to join");
    }
}
