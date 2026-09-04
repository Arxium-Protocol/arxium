// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::{BLOCK_INTERVAL, SKIP_LOG_INTERVAL, STALL_SUSPECT_AFTER, now_secs};
use anyhow::{Ok, Result};
use ed25519_dalek::SigningKey;
use arxd_finality::FinalityEvent;
use metrics::{counter, gauge, histogram};
use xc_runtime_api::ChainRuntime;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use xc_runtime_api::DispatchCtx;
use xc_executor::{execute_actions, resolve_matured_unbonding};
use xc_mempool::Mempool;
use xc_primitives::{Action, Address, Block, eligible_proposer, quorum};
use xc_storage::{ArxiumDb, BatchWritable, ValidatorSetSnapshot};

/// Build, execute, and store the next block using whatever actions are provided.
/// The stored block only lists the actions that were actually applied — see
/// `execute_actions` for why a subset can be dropped.
///
/// `proposer` is `Some((address, key))` when this node is a validator whose
/// turn it is to produce — the block gets signed. `produce_loop` never
/// calls this with `None` (a non-validator node doesn't produce at all);
/// unsigned blocks remain reachable here only from tests.
pub fn produce_block<R: ChainRuntime>(
    db: &ArxiumDb,
    actions: Vec<Action<R::Payload>>,
    timestamp: u64,
    proposer: Option<(&Address, &SigningKey)>,
) -> Result<Block<R::Payload>> {
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    let next_height = tip_height + 1;
    let parent: Block<R::Payload> = db
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
        mut asset_updates,
        asset_registrations,
        attestor_registrations,
        attestor_deregistrations,
    ) = execute_actions(
        db,
        actions,
        &validators,
        seed,
        |action, view, operator_lookup, operator_validators_lookup, validators| {
            R::dispatch(
                action,
                &DispatchCtx {
                    view,
                    db,
                    operator_lookup,
                    operator_validators_lookup,
                    validators,
                    height: next_height,
                },
            )
        },
        None,
    )?;

    // Same whole-block economics `accept_block` applies to a gossiped block
    // — a locally-produced block must pay itself the same way, or a solo
    // validator would never see its own reward pool debited/credited.
    if let Some((address, _)) = proposer {
        let fees_collected = applied.len() as u128 * R::action_fee();
        let mut view = xc_storage::BlockView::new(db);
        view.apply_accounts(&account_updates)?;
        view.apply_stakes(&stake_updates)?;
        view.apply_asset_balances(&asset_updates)?;
        let sealed_updates = R::on_block_sealed(&view, address, fees_collected, &validators, next_height)?;
        account_updates.0.extend(sealed_updates.accounts.0);
        stake_updates.allocations.extend(sealed_updates.stakes.allocations);
        stake_updates.validator_index.extend(sealed_updates.stakes.validator_index);
        asset_updates.0.extend(sealed_updates.assets.0);
    }

    let snapshot = if validator_changes.is_empty() {
        None
    } else {
        Some(ValidatorSetSnapshot {
            effective_height: next_height + 1,
            validators: xc_executor::apply_validator_changes(validators, &validator_changes),
        })
    };

    // The root a validator on the receiving end will independently
    // recompute from the same overlay before accepting this block — must be
    // known before signing, since the signature covers it.
    let state_root_overlay: Vec<&dyn BatchWritable> = {
        let mut overlay: Vec<&dyn BatchWritable> = vec![&account_updates, &stake_updates, &asset_updates];
        if let Some(snapshot) = &snapshot {
            overlay.push(snapshot);
        }
        for registration in &attestor_registrations {
            overlay.push(registration);
        }
        for deregistration in &attestor_deregistrations {
            overlay.push(deregistration);
        }
        overlay
    };
    // The denominator against which PoE cost must be judged: this rescans
    // the entire accounts/validators column families (O(total state), not
    // O(delta)) on every block, so it's the number that decides whether
    // tx_root/block_ep are actually cheap or just cheap next to something
    // already pathological.
    let sr_start = Instant::now();
    let state_root = db.compute_state_root(&state_root_overlay)?;
    histogram!("arxium_state_root_nanos").record(sr_start.elapsed().as_nanos() as f64);

    // `tx_root` is signed as part of the block header (see
    // `xc_primitives::Block::signing_bytes`) — computed once here and reused
    // both for that and for the (still observation-only) EP hash below.
    // Timed separately from `block_ep` below: this is the part that scales
    // with block size (bincode encode + SHA-256 per action + Merkle tree),
    // whereas `block_ep` is a fixed handful of hashes regardless of load.
    let txr_start = Instant::now();
    let tx_root = xc_poe::tx_root(&applied)?;
    histogram!("arxium_poe_tx_root_nanos").record(txr_start.elapsed().as_nanos() as f64);

    // PoE v5 (observation-only, see PoE_v5_design.md): logs and times the
    // execution-proof hash but doesn't touch the signed block or wire
    // format yet — purely to measure EP compute cost against real block
    // production time before it's wired into consensus.
    let poe_start = Instant::now();
    let ep = xc_poe::block_ep(&parent.state_root, &tx_root, &state_root);
    histogram!("arxium_poe_ep_compute_nanos").record(poe_start.elapsed().as_nanos() as f64);
    info!(height = next_height, ep = %hex::encode(ep), "computed proof-of-execution hash");

    // Which round this node is producing for, and — if it isn't round 0 —
    // the certificate proving the round(s) before it timed out. Read fresh
    // here (rather than threaded through from `produce_loop`'s eligibility
    // check) so this stays correct however `produce_block` is called,
    // including directly from tests. See `xc_primitives::Block::round`.
    let round = db.current_round(next_height)?;
    let round_certificate =
        if round == 0 { None } else { db.get_round_certificate(next_height, round - 1)? };

    let mut new_block = Block {
        height: next_height,
        parent_hash: parent.hash(),
        timestamp,
        actions: applied,
        tx_root,
        proposer: None,
        signature: None,
        state_root,
        round,
        round_certificate,
    };
    if let Some((address, key)) = proposer {
        new_block.sign(address.clone(), key);
    }
    // One atomic write for the block record, the account changes it caused,
    // any stake-allocation changes (dispatched actions plus matured
    // unbonding resolved above), and (if any) the resulting validator-set
    // change — a crash here must never leave these disagreeing (e.g. nonces
    // bumped with no block on record for it, or vice versa).
    // Same read-side asset indexes `accept_block` writes — a locally produced
    // block has to index itself, or a solo validator would serve empty asset
    // listings for blocks it authored. `CF_META` only, so the state root
    // signed above is unaffected.
    let asset_index = db.asset_index_updates(&asset_registrations, &asset_updates)?;

    let mut writables: Vec<&dyn BatchWritable> = vec![&account_updates, &stake_updates, &asset_updates];
    if !asset_index.is_empty() {
        writables.push(&asset_index);
    }
    if let Some(snapshot) = &snapshot {
        writables.push(snapshot);
    }
    for marker in &evidence_markers {
        writables.push(marker);
    }
    for registration in &bls_keys {
        writables.push(registration);
    }
    for asset in &asset_registrations {
        writables.push(asset);
    }
    for registration in &attestor_registrations {
        writables.push(registration);
    }
    for deregistration in &attestor_deregistrations {
        writables.push(deregistration);
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
pub fn produce_loop<R: ChainRuntime>(
    db: &ArxiumDb,
    mempool: &Arc<Mutex<Mempool<R::Payload>>>,
    identity: Option<(Address, SigningKey)>,
    chain_lock: &Arc<Mutex<()>>,
    finality_event_tx: &std_mpsc::Sender<FinalityEvent<R::Payload>>,
    block_tx: &tokio::sync::mpsc::UnboundedSender<Block<R::Payload>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    // Rate-limit state for the skip log below. Local because `produce_loop`
    // owns its thread — no lock needed, and no risk of two producers sharing
    // a window.
    let mut last_skip_log: Option<Instant> = None;

    // A plain `thread::sleep(BLOCK_INTERVAL)` at the top of the loop makes
    // the real period `BLOCK_INTERVAL + work_time`, compounding every single
    // iteration — production drifts later and later under load. Ticking off
    // a monotonic deadline instead makes the period converge to
    // `max(BLOCK_INTERVAL, work_time)`.
    let mut next_tick = Instant::now();

    loop {
        thread::sleep(next_sleep(&mut next_tick, Instant::now(), BLOCK_INTERVAL));

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
                let parent: Block<R::Payload> = db
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

                // How much of the set can actually vote on finality. A
                // validator only precommits if it has a registered BLS key,
                // and nothing requires one — genesis carries none, and
                // `JoinValidator` enforces a stake floor but not a key. So a
                // set can be entirely healthy for block production and still
                // be structurally unable to reach a finality quorum, with no
                // symptom but a warn per dropped vote. Exported so the
                // shortfall is alertable before it matters:
                //   arxium_validators_with_bls_key < arxium_finality_quorum
                let voters = validators
                    .iter()
                    .filter(|v| db.get_bls_pubkey(v).ok().flatten().is_some())
                    .count();
                gauge!("arxium_validators_total").set(validators.len() as f64);
                gauge!("arxium_validators_with_bls_key").set(voters as f64);
                gauge!("arxium_finality_quorum").set(quorum(validators.len()) as f64);

                // Eligibility itself no longer comes from `elapsed` — see
                // `xc_primitives::eligible_proposer`'s doc comment (B1b).
                // `elapsed` (and the heuristic `round` derived from it below)
                // survive purely for the stall logging: they're this node's
                // own clock's opinion of how overdue the height is, used to
                // decide when to escalate a log line from info to warn, not
                // to decide who may propose.
                let round = db.current_round(next_height)?;
                gauge!("arxium_consensus_round").set(round as f64);
                match eligible_proposer(&validators, next_height, round) {
                    Some(expected) if &expected == address => {
                        gauge!("arxium_is_expected_proposer").set(1.0);
                        Some((address, key))
                    }
                    // Skipping is normal — it's simply another validator's
                    // turn. Skipping *forever* is the failure mode that took
                    // ~17 hours to notice, and it used to be a bare
                    // `continue` with nothing logged and nothing counted.
                    //
                    // Deliberately not a proposer-address gauge: a label
                    // carrying an address goes stale the moment the proposer
                    // changes and sits at 1 forever. "Is it my turn" is the
                    // question an operator actually has, and it's a plain
                    // 0/1 with no cardinality.
                    Some(expected) => {
                        gauge!("arxium_is_expected_proposer").set(0.0);
                        counter!("arxium_production_skipped_not_eligible_total").increment(1);

                        let due = last_skip_log
                            .map(|at| at.elapsed() >= SKIP_LOG_INTERVAL)
                            .unwrap_or(true);
                        if due {
                            last_skip_log = Some(Instant::now());
                            // Every field here is one a post-hoc diagnosis
                            // needs and cannot recover afterwards: which
                            // height, how long the chain has been silent,
                            // which round that put us in, who that round
                            // belongs to, and who this node is.
                            if elapsed >= STALL_SUSPECT_AFTER.as_secs() {
                                warn!(
                                    "not producing height {next_height}: {elapsed}s since the \
                                     parent block (round {round}) — expected proposer is \
                                     {expected}, this node is {address}. Nothing has produced \
                                     for several rotations; the chain may be stalled."
                                );
                            } else {
                                info!(
                                    "not producing height {next_height}: round {round} belongs \
                                     to {expected}, this node is {address} ({elapsed}s since \
                                     the parent block)"
                                );
                            }
                        }
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
        match produce_block::<R>(db, pending, now, proposer) {
            std::result::Result::Ok(block) => {
                info!(
                    "produced block {} with {} action(s), hash={}",
                    block.height,
                    block.actions.len(),
                    block.hash()
                );
                counter!("arxium_blocks_produced_total").increment(1);
                crate::record_tip(block.height, block.timestamp);
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

/// Advances `*next_tick` by one `interval` and returns how long to sleep
/// before it arrives. If the deadline already passed (the previous
/// iteration's body took longer than `interval`), resyncs `*next_tick` to
/// `now` instead of returning a duration that would fire a burst of
/// immediate iterations to "catch up."
fn next_sleep(next_tick: &mut Instant, now: Instant, interval: Duration) -> Duration {
    *next_tick += interval;
    if *next_tick > now {
        *next_tick - now
    } else {
        *next_tick = now;
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use arxd_runtime::{ACTION_FEE, ActionPayload, ChainBlock, CoreChainRuntime, dispatch};
    use std::collections::BTreeMap;
    use xc_executor::BlockUpdates;
    use xc_primitives::{AccountEntry, Snapshot, expected_proposer};

    /// On time: sleeps the full interval, deadline advances by exactly one
    /// interval.
    #[test]
    fn next_sleep_waits_full_interval_when_on_schedule() {
        let now = Instant::now();
        let interval = Duration::from_secs(2);
        let mut next_tick = now;

        let sleep = next_sleep(&mut next_tick, now, interval);

        assert_eq!(sleep, interval);
        assert_eq!(next_tick, now + interval);
    }

    /// Body overran the interval: no negative/huge sleep, and the deadline
    /// resyncs to `now` instead of trying to fire a catch-up burst.
    #[test]
    fn next_sleep_resyncs_instead_of_bursting_when_behind() {
        let deadline_base = Instant::now();
        let interval = Duration::from_secs(2);
        let mut next_tick = deadline_base;
        // Body took 5s against a 2s interval — well past the next deadline.
        let now = deadline_base + Duration::from_secs(5);

        let sleep = next_sleep(&mut next_tick, now, interval);

        assert_eq!(sleep, Duration::ZERO);
        assert_eq!(next_tick, now);
    }

    #[test]
    fn produce_block_applies_transfer_and_advances_tip() {
        let dir =
            std::env::temp_dir().join(format!("arxium-test-produce-block-{}", std::process::id()));
        let db = ArxiumDb::open(&dir).expect("open test db");

        let genesis: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _, _, _, _, _, _, _, _, _) = execute_actions(
            &db,
            genesis.actions.clone(),
            &[],
            BlockUpdates::default(),
            |action, view, operator_lookup, operator_validators_lookup, validators| {
                dispatch(
                    action,
                    view,
                    operator_lookup,
                    operator_validators_lookup,
                    validators,
                    0,
                    &|_, _| -> std::result::Result<bool, xc_storage::StorageError> {
                        std::result::Result::Ok(false)
                    },
                    &|_: &xc_bls::BlsPublicKey| std::result::Result::Ok(None),
                )
            },
            None,
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
            attested_by: None,
            },
        );
        db.write_batch(&Snapshot {
            height: 0,
            chain_name: "test".into(),
            accounts,
            validators: BTreeMap::new(),
            boot_nodes: Vec::new(),
            attestor: None,
        governor: None,
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

        let block = produce_block::<CoreChainRuntime>(&db, vec![transfer], 1, None).unwrap();

        assert_eq!(block.height, 1);
        assert_eq!(
            db.get_account(&alice).unwrap().unwrap().balance,
            2_000_000 - 400 - arxd_runtime::ACTION_FEE
        );
        assert_eq!(db.get_account(&bob).unwrap().unwrap().balance, 400);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A block this node produces must be one its peers accept, at a range of
    /// elapsed times across old slot boundaries — those boundaries no longer
    /// affect eligibility (B1b: round comes from `db.current_round`, not
    /// elapsed time), but timestamp monotonicity/drift rules still apply and
    /// this keeps them exercised. With no `RoundCertificate` persisted,
    /// `current_round` is always 0, so every sweep produces the same primary;
    /// cross-round eligibility is covered separately by `consensus::tests` in
    /// `core/primitives`.
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
                produce_block::<CoreChainRuntime>(&db, vec![], now_secs() - elapsed, Some((&primary_1, key_1)))
                    .unwrap();

            // Exactly the decision `produce_loop` makes before producing.
            let eligible = eligible_proposer(&validators, 2, db.current_round(2).unwrap()).unwrap();
            covered.insert(eligible.clone());
            let key_2 = if eligible == addr_a { &key_a } else { &key_b };
            let block2 =
                produce_block::<CoreChainRuntime>(&db, vec![], now_secs(), Some((&eligible, key_2))).unwrap();

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
                    false,
                    ACTION_FEE,
                    |action, view, operator_lookup, operator_validators_lookup, vals| {
                        dispatch(
                            action, view, operator_lookup,
                            operator_validators_lookup, vals, height,
                            &|_, _| -> std::result::Result<bool, xc_storage::StorageError> {
                                std::result::Result::Ok(false)
                            },
                            &|_: &xc_bls::BlsPublicKey| std::result::Result::Ok(None),
                        )
                    },
                    <CoreChainRuntime as ChainRuntime>::on_block_sealed,
                );
                assert!(
                    result.is_ok(),
                    "peer rejected block {height} produced at elapsed={elapsed}: {:?}",
                    result.err(),
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }

        // No RoundCertificate was ever persisted, so current_round stays 0
        // for every iteration — only the primary is ever eligible for
        // height 2.
        assert_eq!(covered.len(), 1, "eligible_proposer should be pinned to a single validator");
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

        let block1 = produce_block::<CoreChainRuntime>(&db, vec![], 1_000_000, Some((&addr, &key))).unwrap();

        // Clock jumps backwards, and then stands still.
        let block2 = produce_block::<CoreChainRuntime>(&db, vec![], 500_000, Some((&addr, &key))).unwrap();
        assert!(
            block2.timestamp > block1.timestamp,
            "backwards clock produced a non-monotonic block: {} after {}",
            block2.timestamp,
            block1.timestamp,
        );

        let block3 = produce_block::<CoreChainRuntime>(&db, vec![], block2.timestamp, Some((&addr, &key))).unwrap();
        assert!(block3.timestamp > block2.timestamp, "a stalled clock must still advance");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
