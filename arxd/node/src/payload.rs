use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use xc_executor::BlockUpdates;
use xc_primitives::{
    AccountEntry, Action, Address, StakeAllocation, ValidatorChange, ValidatorEntry,
};
use xc_storage::{AccountUpdates, BlsKeyRegistration, EvidenceMarker, StorageError};

/// Devnet Groth16 verifying key, checked into `circuits/identity-zk` — see
/// that crate's module docs for why it isn't from a real trusted-setup
/// ceremony.
const IDENTITY_ZK_VK_BYTES: &[u8] = include_bytes!("../../../circuits/identity-zk/vk.bin");

fn identity_zk_vk() -> &'static circuit_identity_zk::VerifyingKey<Bls12_381> {
    static VK: OnceLock<circuit_identity_zk::VerifyingKey<Bls12_381>> = OnceLock::new();
    VK.get_or_init(|| {
        circuit_identity_zk::VerifyingKey::deserialize_compressed(IDENTITY_ZK_VK_BYTES)
            .expect("checked-in devnet identity-zk verifying key is well-formed")
    })
}

/// Devnet stub — tune once real economics are decided. Below this,
/// `JoinValidator` is rejected before `circuit_staking::apply_stake` even
/// runs: round-robin proposer selection ignores stake size, so without a
/// floor "becoming a validator" would be free.
pub const MIN_VALIDATOR_STAKE: u128 = 1_000;

/// CoreChain's action payload — chain-specific, unlike `Action`/`Block`
/// themselves. A different chain (e.g. `examples/toy-chain`) defines its
/// own payload type and dispatch instead of adding variants here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPayload {
    Transfer {
        to: Address,
        amount: u128,
    },
    /// Self-staking: routed through `circuit_staking::apply_stake` with
    /// `master == validator == sender`, so it's held in the same
    /// `stake_subaccount` mechanism regular delegators use — same balance
    /// check, same "already controlled by another master" rejection, no new
    /// bookkeeping. Takes effect one block after this action lands
    /// (`xc_executor::accept_block`'s effective-height rule) — can't vote
    /// itself into this block's own proposer slot. `stake` on
    /// `ValidatorEntry` is informational only; `ValidatorSetSnapshot` never
    /// persists it, so the `StakeAllocation` for `(sender, sender)` is the
    /// real source of truth for how much a validator has at stake.
    JoinValidator {
        stake: u128,
    },
    /// Self-service removal, now routed through
    /// `circuit_staking::apply_unstake` for the sender's full self-stake
    /// before the `ValidatorChange::Leave` is allowed. Leaving drops you
    /// from the proposer rotation immediately, but the stake sits in
    /// `Unbonding` for `circuit_staking::UNBONDING_BLOCKS` — and stays
    /// slashable that whole time (`circuit_staking::apply_slash` treats
    /// unbonding funds as fair game). Rejected if the sender isn't currently
    /// a validator, or if they're the last one — an empty validator set
    /// means `expected_proposer` returns `None` forever and the chain can
    /// never produce another block (the same deadlock hit live this session
    /// from running `--bootnode` on two machines, self-inflicted here
    /// instead).
    LeaveValidator,
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
    /// height — normally built and submitted by `runtime::spawn_runtime`
    /// when it observes a competing block, never hand-crafted by an
    /// ordinary user. Anyone *could* submit one given the two blocks, but
    /// `runtime::verify_equivocation` is what actually gates the slash, not
    /// who submitted it — so that's fine.
    SubmitEquivocationEvidence {
        block_a: Box<ChainBlock>,
        block_b: Box<ChainBlock>,
    },
    /// Registers the sender's BLS pubkey for finality-certificate
    /// precommit voting (`arxd/finality`). Any address may register — the
    /// key is only meaningful once/if that address is also in the
    /// validator set at some height; no membership check happens here.
    RegisterBlsKey {
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
}

pub type ChainAction = Action<ActionPayload>;
pub type ChainBlock = xc_primitives::Block<ActionPayload>;

/// The payload → circuit mapping `xc_executor::execute_actions` calls per
/// action. This is the only place CoreChain decides what a payload variant
/// means. `validators` is the set as of the start of this block — the same
/// one `accept_block`/`produce_block` will fold this action's
/// `ValidatorChange` onto. `current_height` is the height of the block being
/// built/accepted — needed to timestamp `Stake`/`Unstake`'s unbonding clock.
pub fn dispatch(
    action: &ChainAction,
    lookup: &dyn Fn(&Address) -> Result<Option<AccountEntry>, StorageError>,
    stake_lookup: &dyn Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError>,
    validator_masters_lookup: &dyn Fn(&Address) -> Result<Vec<Address>, StorageError>,
    validators: &[Address],
    current_height: u64,
    evidence_processed: &dyn Fn(u64, &Address) -> Result<bool, StorageError>,
) -> anyhow::Result<BlockUpdates> {
    match &action.payload {
        ActionPayload::Transfer { to, amount } => Ok(BlockUpdates {
            accounts: circuit_account::apply_transfer(
                lookup,
                &action.sender,
                action.nonce,
                to,
                *amount,
            )?,
            ..Default::default()
        }),
        ActionPayload::JoinValidator { stake } => {
            // The floor is on total self-stake, not this call's delta — a
            // validator already at/above it topping up further shouldn't be
            // re-charged the whole minimum again.
            let existing_active = stake_lookup(&action.sender, &action.sender)?
                .map(|a| a.active_amount)
                .unwrap_or(0);
            if existing_active + *stake < MIN_VALIDATOR_STAKE {
                anyhow::bail!(
                    "stake {stake} is below the minimum validator stake {MIN_VALIDATOR_STAKE}"
                );
            }
            let (accounts, stakes) = circuit_staking::apply_stake(
                lookup,
                stake_lookup,
                validator_masters_lookup,
                &action.sender,
                action.nonce,
                &action.sender,
                *stake,
                current_height,
            )?;
            let change =
                ValidatorChange::Join(action.sender.clone(), ValidatorEntry { stake: *stake });
            Ok(BlockUpdates {
                accounts,
                stakes,
                validator_change: Some(change),
                ..Default::default()
            })
        }
        ActionPayload::LeaveValidator => {
            if !validators.contains(&action.sender) {
                anyhow::bail!("{} is not a current validator", action.sender);
            }
            if validators.len() <= 1 {
                anyhow::bail!("cannot remove the last validator, chain would stall forever");
            }
            let self_stake = stake_lookup(&action.sender, &action.sender)?
                .ok_or_else(|| anyhow::anyhow!("{} has no self-stake to unstake", action.sender))?;
            let (accounts, stakes) = circuit_staking::apply_unstake(
                lookup,
                stake_lookup,
                &action.sender,
                action.nonce,
                &action.sender,
                self_stake.active_amount,
                current_height,
            )?;
            Ok(BlockUpdates {
                accounts,
                stakes,
                validator_change: Some(ValidatorChange::Leave(action.sender.clone())),
                ..Default::default()
            })
        }
        ActionPayload::Stake { validator, amount } => {
            let (accounts, stakes) = circuit_staking::apply_stake(
                lookup,
                stake_lookup,
                validator_masters_lookup,
                &action.sender,
                action.nonce,
                validator,
                *amount,
                current_height,
            )?;
            Ok(BlockUpdates {
                accounts,
                stakes,
                ..Default::default()
            })
        }
        ActionPayload::Unstake { validator, amount } => {
            let (accounts, stakes) = circuit_staking::apply_unstake(
                lookup,
                stake_lookup,
                &action.sender,
                action.nonce,
                validator,
                *amount,
                current_height,
            )?;
            Ok(BlockUpdates {
                accounts,
                stakes,
                ..Default::default()
            })
        }
        ActionPayload::SubmitEquivocationEvidence { block_a, block_b } => {
            let evidence = runtime::EquivocationEvidence {
                block_a: (**block_a).clone(),
                block_b: (**block_b).clone(),
            };
            let equivocator = runtime::verify_equivocation(&evidence)
                .map_err(|err| anyhow::anyhow!("invalid equivocation evidence: {err}"))?;
            if evidence_processed(block_a.height, &equivocator)? {
                anyhow::bail!(
                    "equivocation evidence for {equivocator} at height {} already processed",
                    block_a.height
                );
            }

            let masters = validator_masters_lookup(&equivocator)?;
            let master = masters.first().cloned().ok_or_else(|| {
                anyhow::anyhow!("{equivocator} has no stake to slash for equivocation")
            })?;
            let allocation = stake_lookup(&master, &equivocator)?.ok_or_else(|| {
                anyhow::anyhow!("{equivocator} has no active stake allocation to slash")
            })?;
            let total = allocation.active_amount
                + allocation.unbonding.as_ref().map(|u| u.amount).unwrap_or(0);

            let (accounts, stakes) = circuit_staking::apply_slash(
                lookup,
                stake_lookup,
                validator_masters_lookup,
                &equivocator,
                runtime::slash_amount(total),
                circuit_staking::SlashReason::DoubleSign,
                current_height,
            )?;
            Ok(BlockUpdates {
                accounts,
                stakes,
                evidence: Some(EvidenceMarker {
                    height: block_a.height,
                    proposer: equivocator,
                }),
                ..Default::default()
            })
        }
        ActionPayload::RegisterBlsKey { pubkey } => {
            // Reject malformed/off-curve bytes now rather than at the first
            // failed precommit-vote verification later.
            blst::min_pk::PublicKey::from_bytes(pubkey)
                .and_then(|pk| pk.validate())
                .map_err(|_| anyhow::anyhow!("invalid BLS public key"))?;
            let bytes: [u8; 48] = pubkey
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("BLS public key must be 48 bytes"))?;
            Ok(BlockUpdates {
                bls_key: Some(BlsKeyRegistration {
                    address: action.sender.clone(),
                    pubkey: xc_bls::BlsPublicKey(bytes),
                }),
                ..Default::default()
            })
        }
        ActionPayload::VerifyIdentityCredential { proof } => {
            let entry = lookup(&action.sender)?
                .ok_or_else(|| anyhow::anyhow!("account {} not found", action.sender))?;
            let hash_hex = entry
                .identity_hash
                .clone()
                .ok_or_else(|| anyhow::anyhow!("account has no identity_hash to prove"))?;
            let hash_bytes =
                hex::decode(&hash_hex).map_err(|_| anyhow::anyhow!("identity_hash is not valid hex"))?;
            let credential_hash = Fr::deserialize_compressed(hash_bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("identity_hash is not a valid field element"))?;
            let parsed_proof =
                circuit_identity_zk::Proof::<Bls12_381>::deserialize_compressed(proof.as_slice())
                    .map_err(|_| anyhow::anyhow!("malformed zk proof bytes"))?;
            if !circuit_identity_zk::verify(&credential_hash, &parsed_proof, identity_zk_vk()) {
                anyhow::bail!("zk credential proof failed verification");
            }
            let mut verified_entry = entry;
            verified_entry.zk_identity_verified = true;
            Ok(BlockUpdates {
                accounts: AccountUpdates(std::collections::HashMap::from([(
                    action.sender.clone(),
                    verified_entry,
                )])),
                ..Default::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(_addr: &Address) -> Result<Option<AccountEntry>, StorageError> {
        Ok(None)
    }

    fn stake_lookup(
        _master: &Address,
        _validator: &Address,
    ) -> Result<Option<StakeAllocation>, StorageError> {
        Ok(None)
    }

    fn validator_masters_lookup(_validator: &Address) -> Result<Vec<Address>, StorageError> {
        Ok(Vec::new())
    }

    fn make_lookup(
        accounts: HashMap<Address, AccountEntry>,
    ) -> impl Fn(&Address) -> Result<Option<AccountEntry>, StorageError> {
        move |addr| Ok(accounts.get(addr).cloned())
    }

    fn make_stake_lookup(
        allocations: HashMap<(Address, Address), StakeAllocation>,
    ) -> impl Fn(&Address, &Address) -> Result<Option<StakeAllocation>, StorageError> {
        move |master, validator| {
            Ok(allocations
                .get(&(master.clone(), validator.clone()))
                .cloned())
        }
    }

    fn funded(balance: u128) -> AccountEntry {
        AccountEntry {
            balance,
            nonce: 0,
            identity_hash: None,
            zk_identity_verified: false,
        }
    }

    fn self_allocation(addr: &Address, active_amount: u128) -> StakeAllocation {
        StakeAllocation {
            master: addr.clone(),
            validator: addr.clone(),
            active_amount,
            unbonding: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn leave_validator_rejected_when_sender_is_the_last_validator() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let err = match dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[alice],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected leaving the last validator to be rejected"),
        };
        assert!(err.to_string().contains("last validator"));
    }

    #[test]
    fn leave_validator_succeeds_when_others_remain() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            self_allocation(&alice, 2_000),
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[alice.clone(), bob],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();
        assert!(matches!(updates.validator_change, Some(ValidatorChange::Leave(a)) if a == alice));
    }

    #[test]
    fn join_validator_debits_sender_and_credits_own_subaccount() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(5_000))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                stake: MIN_VALIDATOR_STAKE,
            },
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Join(ref a, _)) if *a == alice)
        );
        assert_eq!(
            updates.accounts.0.get(&alice).unwrap().balance,
            5_000 - MIN_VALIDATOR_STAKE
        );
        let sub = circuit_staking::stake_subaccount(&alice);
        assert_eq!(
            updates.accounts.0.get(&sub).unwrap().balance,
            MIN_VALIDATOR_STAKE
        );
        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(allocation.active_amount, MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn second_join_tops_up_rather_than_double_charging() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(10_000))]));
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            self_allocation(&alice, MIN_VALIDATOR_STAKE),
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator { stake: 500 },
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[alice.clone()],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();

        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            allocation.active_amount,
            MIN_VALIDATOR_STAKE + 500,
            "top-up adds to the existing self-stake"
        );
    }

    #[test]
    fn join_validator_rejected_with_insufficient_balance() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(100))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                stake: MIN_VALIDATOR_STAKE,
            },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance")
                || err.to_string().contains("InsufficientBalance")
        );
    }

    #[test]
    fn join_validator_rejected_below_minimum_stake() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::from([(alice.clone(), funded(10_000))]));
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::JoinValidator {
                stake: MIN_VALIDATOR_STAKE - 1,
            },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("minimum validator stake"));
    }

    #[test]
    fn leave_validator_starts_unbonding_rather_than_instant_return() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            self_allocation(&alice, MIN_VALIDATOR_STAKE),
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[alice.clone(), bob],
            5,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();

        assert!(
            matches!(updates.validator_change, Some(ValidatorChange::Leave(ref a)) if *a == alice)
        );
        let allocation = updates
            .stakes
            .allocations
            .get(&(alice.clone(), alice.clone()))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            allocation.active_amount, 0,
            "full self-stake moves out of active"
        );
        let unbonding = allocation
            .unbonding
            .expect("leaving must start an unbonding batch, not an instant refund");
        assert_eq!(unbonding.amount, MIN_VALIDATOR_STAKE);
        assert_eq!(
            unbonding.unlock_at_height,
            5 + circuit_staking::UNBONDING_BLOCKS
        );
        // No balance credited back yet — still sitting in the sub-account, slashable.
        assert_eq!(
            updates
                .accounts
                .0
                .get(&alice)
                .map(|a| a.balance)
                .unwrap_or(0),
            0
        );
    }

    fn signed_chain_block(
        key: &ed25519_dalek::SigningKey,
        height: u64,
        timestamp: u64,
    ) -> ChainBlock {
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let mut block: ChainBlock = xc_primitives::Block::genesis(timestamp);
        block.height = height;
        block.sign(addr, key);
        block
    }

    #[test]
    fn equivocation_evidence_slashes_the_equivocator() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let equivocator = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let block_a = signed_chain_block(&key, 5, 100);
        let block_b = signed_chain_block(&key, 5, 200);

        let sub_account = circuit_staking::stake_subaccount(&equivocator);
        let lookup = make_lookup(HashMap::from([(sub_account, funded(10_000))]));
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (equivocator.clone(), equivocator.clone()),
            self_allocation(&equivocator, 10_000),
        )]));
        let equivocator_for_masters = equivocator.clone();
        let validator_masters_lookup = move |_v: &Address| -> Result<Vec<Address>, StorageError> {
            Ok(vec![equivocator_for_masters.clone()])
        };
        let action = Action {
            sender: equivocator.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SubmitEquivocationEvidence {
                block_a: Box::new(block_a),
                block_b: Box::new(block_b),
            },
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();

        let allocation = updates
            .stakes
            .allocations
            .get(&(equivocator.clone(), equivocator.clone()))
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            allocation.active_amount,
            10_000 - runtime::slash_amount(10_000)
        );
        let marker = updates.evidence.expect("must write an evidence marker");
        assert_eq!(marker.height, 5);
        assert_eq!(marker.proposer, equivocator);
    }

    #[test]
    fn equivocation_evidence_rejected_when_already_processed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let equivocator = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let block_a = signed_chain_block(&key, 5, 100);
        let block_b = signed_chain_block(&key, 5, 200);

        let lookup = make_lookup(HashMap::new());
        let stake_lookup = make_stake_lookup(HashMap::new());
        let action = Action {
            sender: equivocator.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SubmitEquivocationEvidence {
                block_a: Box::new(block_a),
                block_b: Box::new(block_b),
            },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            10,
            &|_, _| Ok::<bool, StorageError>(true),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already processed"));
    }

    #[test]
    fn leave_validator_rejected_while_already_unbonding() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let lookup = make_lookup(HashMap::new());
        // Active portion left nonzero (e.g. a prior manual partial Unstake)
        // so the `amount == 0` guard in apply_unstake doesn't fire first —
        // this test is specifically about the AlreadyUnbonding rejection.
        let mut allocation = self_allocation(&alice, 300);
        allocation.unbonding = Some(xc_primitives::Unbonding {
            amount: 700,
            unlock_at_height: 100,
        });
        let stake_lookup = make_stake_lookup(HashMap::from([(
            (alice.clone(), alice.clone()),
            allocation,
        )]));
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::LeaveValidator,
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[alice.clone(), bob],
            5,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already has an unbonding batch"));
    }

    #[test]
    fn register_bls_key_accepts_a_valid_pubkey() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let (_, pubkey) = xc_bls::keygen_from_seed(&[9u8; 32]).unwrap();
        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                pubkey: pubkey.0.to_vec(),
            },
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();
        let registration = updates.bls_key.expect("expected a bls_key update");
        assert_eq!(registration.address, alice);
        assert_eq!(registration.pubkey.0, pubkey.0);
    }

    #[test]
    fn register_bls_key_rejects_malformed_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::RegisterBlsKey {
                pubkey: vec![0u8; 48],
            },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid BLS public key"));
    }

    #[test]
    fn verify_identity_credential_accepts_a_valid_proof() {
        use ark_serialize::CanonicalSerialize;
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let preimage = b"alice's secret preimage";
        let params = circuit_identity_zk::poseidon_params();
        let hash = circuit_identity_zk::credential_hash(&params, preimage);
        let mut hash_bytes = Vec::new();
        hash.serialize_compressed(&mut hash_bytes).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(preimage, &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut account = funded(0);
        account.identity_hash = Some(hex::encode(hash_bytes));
        let lookup = make_lookup(HashMap::from([(alice.clone(), account)]));
        let stake_lookup = make_stake_lookup(HashMap::new());

        let action = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
        };

        let updates = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap();
        let entry = &updates.accounts.0[&alice];
        assert!(entry.zk_identity_verified);
    }

    #[test]
    fn verify_identity_credential_rejects_malformed_proof_bytes() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let mut account = funded(0);
        account.identity_hash = Some(hex::encode([0u8; 32]));
        let lookup = make_lookup(HashMap::from([(alice.clone(), account)]));
        let stake_lookup = make_stake_lookup(HashMap::new());

        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential {
                proof: vec![0u8; 10],
            },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("malformed zk proof bytes"));
    }

    #[test]
    fn verify_identity_credential_rejects_a_proof_for_the_wrong_hash() {
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pk_bytes: &[u8] = include_bytes!("../../../circuits/identity-zk/pk.bin");
        let pk = circuit_identity_zk::ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes).unwrap();

        let mut rng = StdRng::seed_from_u64(7);
        let proof = circuit_identity_zk::prove(b"the real preimage", &pk, &mut rng);
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();

        // Account's stored identity_hash doesn't match the preimage proven above.
        let params = circuit_identity_zk::poseidon_params();
        let wrong_hash = circuit_identity_zk::credential_hash(&params, b"a different preimage");
        let mut wrong_hash_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&wrong_hash, &mut wrong_hash_bytes).unwrap();

        let mut account = funded(0);
        account.identity_hash = Some(hex::encode(wrong_hash_bytes));
        let lookup = make_lookup(HashMap::from([(alice.clone(), account)]));
        let stake_lookup = make_stake_lookup(HashMap::new());

        let action = Action {
            sender: alice,
            nonce: 0,
            signature: None,
            payload: ActionPayload::VerifyIdentityCredential { proof: proof_bytes },
        };

        let err = dispatch(
            &action,
            &lookup,
            &stake_lookup,
            &validator_masters_lookup,
            &[],
            0,
            &|_, _| Ok::<bool, StorageError>(false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed verification"));
    }
}
