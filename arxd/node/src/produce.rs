use crate::payload::{ACTION_FEE, ActionPayload, ChainBlock, dispatch};
use crate::{BLOCK_INTERVAL, SLOT_DURATION, now_secs};
use anyhow::{Ok, Result};
use ed25519_dalek::SigningKey;
use finality::FinalityEvent;
use metrics::{counter, gauge};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::{info, warn};
use xc_executor::{execute_actions, resolve_matured_unbonding};
use xc_mempool::Mempool;
use xc_primitives::{Action, Address, eligible_proposer, expected_proposer};
use xc_storage::{ArxiumDb, BatchWritable, ValidatorSetSnapshot};

/// Build, execute, and store the next block using whatever actions are provided.
/// The stored block only lists the actions that were actually applied — see
/// `execute_actions` for why a subset can be dropped.
///
/// `proposer` is `Some((address, key))` when this node is a validator whose
/// turn it is to produce — the block gets signed. `produce_loop` never
/// calls this with `None` (a non-validator node doesn't produce at all);
/// unsigned blocks remain reachable here only from tests.
pub fn produce_block(
    db: &ArxiumDb,
    actions: Vec<Action<ActionPayload>>,
    timestamp: u64,
    proposer: Option<(&Address, &SigningKey)>,
) -> Result<ChainBlock> {
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    let next_height = tip_height + 1;
    let parent: ChainBlock = db
        .get_block(tip_height)?
        .expect("tip block must exist if tip_height is set");

    // `accept_block` rejects a block whose timestamp doesn't advance past its
    // parent's, so a node must never produce one — otherwise a backwards step
    // in the host clock, or simply two blocks landing inside the same second,
    // would make every peer reject a block this node considers valid, and the
    // producer would be the last to know.
    //
    // Clamping up by one second doesn't change who was eligible: the caller
    // already decided that from `now - parent.timestamp`, and any clamped
    // value lands inside the same slot (round 0) as the elapsed time that
    // produced it, for any slot duration above 1s. Genesis is exempt from the
    // monotonicity rule, and its timestamp is 0, so the clamp is a no-op there.
    let timestamp = timestamp.max(parent.timestamp + 1);

    // Pre-block set — matches `xc_executor::accept_block`'s
    // `get_validator_set_at(block.height)` exactly, so a self-produced block
    // and a gossiped/synced one fold JoinValidator/LeaveValidator the same way.
    let validators = db.get_validator_set_at(next_height)?;
    let seed = resolve_matured_unbonding(db, next_height)?;
    let (
        applied,
        mut account_updates,
        validator_changes,
        mut stake_updates,
        evidence_markers,
        bls_keys,
        operator_updates,
    ) = execute_actions(
        db,
        actions,
        &validators,
        seed,
        |action, lookup, stake_lookup, validator_masters_lookup, operator_lookup, operator_validators_lookup, validators| {
            dispatch(
                action,
                lookup,
                stake_lookup,
                validator_masters_lookup,
                operator_lookup,
                operator_validators_lookup,
                validators,
                next_height,
                &|h, p| db.evidence_processed(h, p),
            )
        },
    )?;

    // Same block-reward split `accept_block` applies to a gossiped block —
    // a locally-produced block must pay itself the same way, or a solo
    // validator would never see its own reward pool debited/credited.
    if let Some((address, _)) = proposer {
        let fees_collected = applied.len() as u128 * ACTION_FEE;
        let account_lookup = |addr: &Address| match account_updates.0.get(addr) {
            Some(entry) => std::result::Result::Ok(Some(entry.clone())),
            None => db.get_account(addr),
        };
        let reward_updates =
            circuit_staking::apply_block_reward(account_lookup, address, fees_collected)?;
        account_updates.0.extend(reward_updates.0);

        // §7.3 downtime slash — same rule `accept_block` applies to a
        // gossiped block: if the height's primary round-robin proposer
        // wasn't the one who actually produced it, burn a small automatic
        // slash from their stake.
        if let Some(primary) = expected_proposer(&validators, next_height) {
            let account_lookup = |addr: &Address| match account_updates.0.get(addr) {
                Some(entry) => std::result::Result::Ok(Some(entry.clone())),
                None => db.get_account(addr),
            };
            let allocation_lookup = |m: &Address, v: &Address| {
                match stake_updates.allocations.get(&(m.clone(), v.clone())) {
                    Some(a) => std::result::Result::Ok(a.clone()),
                    None => db.get_stake_allocation(m, v),
                }
            };
            let masters_lookup = |v: &Address| match stake_updates.validator_index.get(v) {
                Some(m) => std::result::Result::Ok(m.clone()),
                None => db.get_stakes_by_validator(v),
            };
            let (downtime_accounts, downtime_stakes) = circuit_staking::apply_downtime_slash(
                account_lookup,
                allocation_lookup,
                masters_lookup,
                &primary,
                address,
                next_height,
            )?;
            account_updates.0.extend(downtime_accounts.0);
            stake_updates.allocations.extend(downtime_stakes.allocations);
            stake_updates.validator_index.extend(downtime_stakes.validator_index);
        }
    }

    let mut new_block = ChainBlock {
        height: next_height,
        parent_hash: parent.hash(),
        timestamp,
        actions: applied,
        proposer: None,
        signature: None,
    };
    if let Some((address, key)) = proposer {
        new_block.sign(address.clone(), key);
    }
    // One atomic write for the block record, the account changes it caused,
    // any stake-allocation changes (dispatched actions plus matured
    // unbonding resolved above), and (if any) the resulting validator-set
    // change — a crash here must never leave these disagreeing (e.g. nonces
    // bumped with no block on record for it, or vice versa).
    let mut writables: Vec<&dyn BatchWritable> = vec![&account_updates, &stake_updates];
    let snapshot = if validator_changes.is_empty() {
        None
    } else {
        Some(ValidatorSetSnapshot {
            effective_height: next_height + 1,
            validators: xc_executor::apply_validator_changes(validators, &validator_changes),
        })
    };
    if let Some(snapshot) = &snapshot {
        writables.push(snapshot);
    }
    for marker in &evidence_markers {
        writables.push(marker);
    }
    for registration in &bls_keys {
        writables.push(registration);
    }
    writables.push(&operator_updates);
    writables.push(&new_block);
    db.write_batches(&writables)?;

    Ok(new_block)
}

/// Ticks every `BLOCK_INTERVAL`, producing a signed block when this node is
/// the validator whose turn it is. A non-validator node (`identity: None`)
/// never produces — it only accepts blocks gossiped/synced from peers (see
/// `accept_block`). Runs until `shutdown` is set, e.g. by the ctrl_c handler
/// spawned in `run`.
pub fn produce_loop(
    db: &ArxiumDb,
    mempool: &Arc<Mutex<Mempool<ActionPayload>>>,
    identity: Option<(Address, SigningKey)>,
    chain_lock: &Arc<Mutex<()>>,
    finality_event_tx: &std_mpsc::Sender<FinalityEvent<ActionPayload>>,
    block_tx: &tokio::sync::mpsc::UnboundedSender<ChainBlock>,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    loop {
        thread::sleep(BLOCK_INTERVAL);

        if shutdown.load(Ordering::Relaxed) {
            info!("shutting down");
            return Ok(());
        }

        // Held for the whole read-tip / decide / write cycle, so a block
        // accepted from gossip in between can't make this node produce a
        // second, conflicting block for the height it just filled — the
        // recomputed `next_height` below will already have moved past it.
        let guard = chain_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Captured once, and used both to decide eligibility below and to
        // stamp the block that results. These used to be two separate
        // `now_secs()` calls with the mempool drain and full block execution
        // in between, so a second ticking across a slot boundary meant the
        // producer decided it was eligible at one round while every peer
        // recomputed eligibility from the *stamped* timestamp and got a
        // different round — rejecting the block as WrongProposer. That is the
        // exact shape of the captured incident recorded in
        // `Arxium_OpenItems.md` §3, where block 202 was stamped at :02 and
        // committed at :04. One reading makes producer and validator agree
        // by construction.
        let now = now_secs();

        let proposer = match &identity {
            Some((address, key)) => {
                let tip_height = db.get_tip_height()?.unwrap_or(0);
                let next_height = tip_height + 1;
                let parent: ChainBlock = db
                    .get_block(tip_height)?
                    .expect("tip block must exist if tip_height is set");
                // Genesis's timestamp is a synthetic 0, not a real
                // wall-clock moment — see the matching comment in
                // `accept_block`. Height 1 always uses the plain primary.
                let elapsed = if parent.height == 0 {
                    0
                } else {
                    now.saturating_sub(parent.timestamp)
                };
                let validators = db.get_validator_set_at(next_height)?;
                match eligible_proposer(&validators, next_height, elapsed, SLOT_DURATION.as_secs())
                {
                    Some(expected) if &expected == address => Some((address, key)),
                    Some(_) => {
                        drop(guard);
                        continue;
                    }
                    None => {
                        warn!("no validators registered, skipping block production");
                        drop(guard);
                        continue;
                    }
                }
            }
            // Not a validator: nothing to propose with, and no business
            // producing blocks at all — this node only accepts blocks
            // from peers. Previously fell through to `produce_block` with
            // `proposer: None`, which produced an unsigned block anyway.
            None => {
                drop(guard);
                continue;
            }
        };

        gauge!("arxium_mempool_pending_actions")
            .set(mempool.lock().unwrap_or_else(|e| e.into_inner()).len() as f64);

        let pending = mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_pending(100);
        // Empty blocks still get produced — height must keep advancing on
        // schedule so `expected_proposer` round-robin doesn't stall waiting
        // for someone to submit an action.
        // A bad action (forged signature, stale nonce) is skipped by execute_actions
        // and never reaches here; an Err means block-level bookkeeping itself failed
        // (e.g. storage), which is unexpected and logged rather than propagated.
        match produce_block(db, pending, now, proposer) {
            std::result::Result::Ok(block) => {
                info!(
                    "produced block {} with {} action(s), hash={}",
                    block.height,
                    block.actions.len(),
                    block.hash()
                );
                counter!("arxium_blocks_produced_total").increment(1);
                gauge!("arxium_tip_height").set(block.height as f64);
                // Only signed blocks are meaningful to peers — an unsigned
                // block (non-validator solo mode) has no proposer for
                // `accept_block`'s expected-proposer check to match.
                if block.signature.is_some() {
                    let _ = finality_event_tx.send(FinalityEvent::BlockObserved(block.clone()));
                    let _ = block_tx.send(block);
                }
            }
            Err(err) => {
                warn!("block production failed: {err}");
                counter!("arxium_block_production_errors_total").increment(1);
            }
        }
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use xc_executor::BlockUpdates;
    use xc_primitives::{AccountEntry, Snapshot};

    #[test]
    fn produce_block_applies_transfer_and_advances_tip() {
        let dir =
            std::env::temp_dir().join(format!("arxium-test-produce-block-{}", std::process::id()));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let genesis: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _, _, _, _, _) = execute_actions(
            &db,
            genesis.actions.clone(),
            &[],
            BlockUpdates::default(),
            |action, lookup, stake_lookup, validator_masters_lookup, operator_lookup, operator_validators_lookup, validators| {
                dispatch(
                    action,
                    lookup,
                    stake_lookup,
                    validator_masters_lookup,
                    operator_lookup,
                    operator_validators_lookup,
                    validators,
                    0,
                    &|_, _| -> std::result::Result<bool, xc_storage::StorageError> {
                        std::result::Result::Ok(false)
                    },
                )
            },
        )
        .unwrap();
        db.write_batches(&[&genesis_updates, &genesis]).unwrap();

        let alice_key = SigningKey::from_bytes(&[1u8; 32]);
        let alice = Address::from_pubkey_bytes(alice_key.verifying_key().as_bytes()).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();

        let mut accounts = BTreeMap::new();
        accounts.insert(
            alice.clone(),
            AccountEntry {
                balance: 2_000_000,
                nonce: 0,
                identity_hash: None,
                zk_identity_verified: false,
            },
        );
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts,
            validators: BTreeMap::new(),
            boot_nodes: Vec::new(),
        })
        .unwrap();

        let mut transfer = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::Transfer {
                to: bob.clone(),
                amount: 400,
            },
        };
        let signature = alice_key.sign(&transfer.signing_bytes());
        transfer.signature = Some(hex::encode(signature.to_bytes()));

        let block = produce_block(&db, vec![transfer], 1, None).unwrap();

        assert_eq!(block.height, 1);
        assert_eq!(
            db.get_account(&alice).unwrap().unwrap().balance,
            2_000_000 - 400 - crate::payload::ACTION_FEE
        );
        assert_eq!(db.get_account(&bob).unwrap().unwrap().balance, 400);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A block this node produces must be one its peers accept. `produce_loop`
    /// picks the producer from `eligible_proposer` using `now - parent`, while
    /// `accept_block` re-derives it from the block's *stamped* timestamp — so
    /// this walks a two-validator rotation across slot boundaries, has whichever
    /// validator is eligible at that elapsed time produce, and requires a peer
    /// to accept it. Two validators (not one) is the point: with a single
    /// validator `eligible_proposer` returns the same address at every round
    /// and the assertion would hold vacuously.
    #[test]
    fn a_produced_block_is_accepted_by_the_same_rules_that_validate_a_gossiped_one() {
        let key_a = SigningKey::from_bytes(&[21u8; 32]);
        let key_b = SigningKey::from_bytes(&[22u8; 32]);
        let addr_a = Address::from_pubkey_bytes(key_a.verifying_key().as_bytes()).unwrap();
        let addr_b = Address::from_pubkey_bytes(key_b.verifying_key().as_bytes()).unwrap();
        let mut validators = vec![addr_a.clone(), addr_b.clone()];
        validators.sort();

        // Boundaries on both sides of every slot edge, plus rounds past a full
        // cycle — where the old capped implementation stopped rotating.
        let mut covered = std::collections::HashSet::new();
        for elapsed in [0u64, 3, 4, 7, 8, 11, 12, 16, 20, 100] {
            let dir = std::env::temp_dir().join(format!(
                "arxium-test-produce-accept-{}-{}-{}",
                std::process::id(),
                elapsed,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            let db = ArxiumDb::open(&dir).expect("open test db");
            db.write_batch(&ValidatorSetSnapshot {
                effective_height: 0,
                validators: validators.clone(),
            })
            .unwrap();
            let genesis: ChainBlock = xc_primitives::Block::genesis(0);
            db.write_batches(&[&genesis]).unwrap();

            // Height 1 is exempt from the timestamp rules and always goes to
            // the plain primary, so establish it first and test height 2.
            // The parent sits `elapsed` seconds in the *past* and the child
            // stamps at `now` — the real arrangement. Stamping the child
            // `elapsed` into the future instead would trip the drift bound,
            // which is a different rule and correctly enforced elsewhere.
            let primary_1 = expected_proposer(&validators, 1).unwrap();
            let key_1 = if primary_1 == addr_a { &key_a } else { &key_b };
            let block1 =
                produce_block(&db, vec![], now_secs() - elapsed, Some((&primary_1, key_1)))
                    .unwrap();

            // Exactly the decision `produce_loop` makes before producing.
            let eligible =
                eligible_proposer(&validators, 2, elapsed, SLOT_DURATION.as_secs()).unwrap();
            covered.insert(eligible.clone());
            let key_2 = if eligible == addr_a { &key_a } else { &key_b };
            let block2 =
                produce_block(&db, vec![], now_secs(), Some((&eligible, key_2))).unwrap();

            // Re-validate on a fresh chain holding the same history, the way a
            // peer receiving these over gossip would.
            let peer = ArxiumDb::open(&dir.join("peer")).expect("open peer db");
            peer.write_batch(&ValidatorSetSnapshot {
                effective_height: 0,
                validators: validators.clone(),
            })
            .unwrap();
            peer.write_batches(&[&genesis]).unwrap();

            for (block, height) in [(block1, 1u64), (block2, 2)] {
                let result = xc_executor::accept_block(
                    &peer,
                    block,
                    SLOT_DURATION.as_secs(),
                    false,
                    ACTION_FEE,
                    |action, lookup, stake_lookup, validator_masters_lookup, operator_lookup, operator_validators_lookup, vals| {
                        dispatch(
                            action, lookup, stake_lookup, validator_masters_lookup, operator_lookup,
                            operator_validators_lookup, vals, height,
                            &|_, _| -> std::result::Result<bool, xc_storage::StorageError> {
                                std::result::Result::Ok(false)
                            },
                        )
                    },
                );
                assert!(
                    result.is_ok(),
                    "peer rejected block {height} produced at elapsed={elapsed}: {:?}",
                    result.err(),
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }

        // The sweep has to have actually exercised both validators, or the
        // agreement it proves is the vacuous single-validator one.
        assert_eq!(covered.len(), 2, "rotation never handed height 2 to both validators");
    }

    /// A produced block always advances past its parent's timestamp, even when
    /// the host clock doesn't — otherwise peers reject it for non-monotonicity
    /// and the producer is the last to find out.
    #[test]
    fn a_produced_block_always_advances_past_its_parent_timestamp() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-produce-monotonic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let key = SigningKey::from_bytes(&[22u8; 32]);
        let addr = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        db.write_batch(&ValidatorSetSnapshot {
            effective_height: 0,
            validators: vec![addr.clone()],
        })
        .unwrap();
        let genesis: ChainBlock = xc_primitives::Block::genesis(0);
        db.write_batches(&[&genesis]).unwrap();

        let block1 = produce_block(&db, vec![], 1_000_000, Some((&addr, &key))).unwrap();

        // Clock jumps backwards, and then stands still.
        let block2 = produce_block(&db, vec![], 500_000, Some((&addr, &key))).unwrap();
        assert!(
            block2.timestamp > block1.timestamp,
            "backwards clock produced a non-monotonic block: {} after {}",
            block2.timestamp,
            block1.timestamp,
        );

        let block3 = produce_block(&db, vec![], block2.timestamp, Some((&addr, &key))).unwrap();
        assert!(block3.timestamp > block2.timestamp, "a stalled clock must still advance");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
