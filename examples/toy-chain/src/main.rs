// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Toy Chain: RWA (real-world-asset) sovereign chain MVP built purely on
//! `core/` + `circuits/rwa-asset`, with no dependency on `arxd/*`. It exists
//! to answer one question honestly: does the `core/` design (generic
//! `Action<P>`/`Block<P>`, dispatch-closure executor) actually hold up for a
//! chain with *different* execution semantics than CoreChain's plain
//! `Transfer`? So its payload is its own `RwaPayload` (`Issue`,
//! compliance-gated `Transfer`), not CoreChain's.
//!
//! Runs a fixed sequence of blocks against a fresh on-disk DB: the issuer
//! mints supply to itself, transfers some to a KYC'd account (succeeds),
//! then attempts a transfer to a non-KYC'd account (rejected by the
//! compliance check, dropped rather than applied) — no RPC, no networking,
//! no CLI.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use tracing::info;
use xc_executor::{BlockUpdates, execute_actions};
use xc_mempool::Mempool;
use xc_primitives::{Action, Address, Block, ValidatorChange};
use xc_storage::{AccountUpdates, ArxiumDb, BlockView};

/// toy-chain's own preset registry — proof that `PresetRegistry` works for a
/// second, differently-shaped chain with zero dependency on `arxd/node` or
/// any of CoreChain's genesis data. The three fixed genesis accounts below
/// (issuer, KYC'd recipient, non-KYC'd recipient) live in
/// `specs/toy-chain-dev.json`, not hand-rolled here — same shared
/// chain-spec path CoreChain's `devnet`/`local` presets use.
static TOY_CHAIN_PRESETS: xc_chain_spec::presets::PresetRegistry =
    xc_chain_spec::presets::PresetRegistry::new(&[("dev", include_str!("../specs/toy-chain-dev.json"))]);

/// The RWA chain's own action set — distinct from CoreChain's `ActionPayload`
/// in `arxd/node`, proving payloads are chain-specific rather than one
/// shared enum.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum RwaPayload {
    Issue { amount: u128 },
    Transfer { to: Address, amount: u128 },
}

type RwaAction = Action<RwaPayload>;
type RwaBlock = Block<RwaPayload>;

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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_action(key: &SigningKey, sender: &Address, nonce: u64, payload: RwaPayload) -> RwaAction {
    let mut action = Action {
        sender: sender.clone(),
        nonce,
        signature: None,
        payload,
    };
    let signature = key.sign(&action.signing_bytes());
    action.signature = Some(hex::encode(signature.to_bytes()));
    action
}

fn produce_block(
    db: &ArxiumDb,
    actions: Vec<RwaAction>,
    issuer: &Address,
    timestamp: u64,
) -> Result<RwaBlock> {
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    let parent: RwaBlock = db.get_block(tip_height)?.expect("tip block must exist");

    let (applied, updates, _, _, _, _, _) = execute_actions(
        db,
        actions,
        &[],
        BlockUpdates::default(),
        |action, view, _operator_lookup, _operator_validators_lookup, _validators| {
            let (accounts, validator_change) = dispatch(action, view, issuer)?;
            Ok(BlockUpdates {
                accounts,
                validator_change,
                ..Default::default()
            })
        },
    )?;

    let block = Block {
        height: tip_height + 1,
        parent_hash: parent.hash(),
        timestamp,
        actions: applied,
        proposer: None,
        signature: None,
        // toy-chain doesn't implement state-root verification — it exists to
        // exercise `core`'s generic boundaries, not to be a second real chain.
        state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    };
    db.write_batches(&[&updates, &block])?;
    Ok(block)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let dir = std::env::temp_dir().join(format!("arxium-toy-chain-rwa-{}", std::process::id()));
    let db = ArxiumDb::open(&dir)?;

    let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
    let issuer = Address::from_pubkey_bytes(issuer_key.verifying_key().as_bytes())?;
    let kyc_recipient = Address::from_pubkey_bytes(&[2u8; 32])?;
    let non_kyc_recipient = Address::from_pubkey_bytes(&[3u8; 32])?;

    let spec_json = xc_chain_spec::resolve_chain_spec("dev", &TOY_CHAIN_PRESETS)
        .context("failed to resolve toy-chain genesis spec")?;
    let snapshot =
        xc_chain_spec::load_or_init_snapshot(&dir, &spec_json).context("failed to load toy-chain genesis spec")?;
    db.write_batch(&snapshot)?;
    let genesis: RwaBlock = Block::genesis(now());
    db.write_batches(&[
        &execute_actions(
            &db,
            genesis.actions.clone(),
            &[],
            BlockUpdates::default(),
            |action, view, _operator_lookup, _operator_validators_lookup, _validators| {
                let (accounts, validator_change) = dispatch(action, view, &issuer)?;
                Ok(BlockUpdates {
                    accounts,
                    validator_change,
                    ..Default::default()
                })
            },
        )?
        .1,
        &genesis,
    ])?;

    let mut mempool: Mempool<RwaPayload> = Mempool::new();

    // Issuer mints 1000 units of the asset to itself.
    mempool.push(sign_action(
        &issuer_key,
        &issuer,
        0,
        RwaPayload::Issue { amount: 1_000 },
    ))?;
    let block = produce_block(&db, mempool.drain_pending(1), &issuer, now())?;
    info!(
        "block {}: issued supply, issuer balance={}",
        block.height,
        db.get_account(&issuer)?.unwrap().balance
    );

    // Compliant transfer: both issuer and recipient are KYC'd — must succeed.
    mempool.push(sign_action(
        &issuer_key,
        &issuer,
        1,
        RwaPayload::Transfer {
            to: kyc_recipient.clone(),
            amount: 400,
        },
    ))?;
    let block = produce_block(&db, mempool.drain_pending(1), &issuer, now())?;
    info!(
        "block {}: compliant transfer applied, issuer={} kyc_recipient={}",
        block.height,
        db.get_account(&issuer)?.unwrap().balance,
        db.get_account(&kyc_recipient)?.unwrap().balance
    );
    assert_eq!(block.actions.len(), 1, "compliant transfer must be applied");

    // Non-compliant transfer: recipient isn't KYC'd — executor must drop it,
    // not apply it silently.
    mempool.push(sign_action(
        &issuer_key,
        &issuer,
        2,
        RwaPayload::Transfer {
            to: non_kyc_recipient.clone(),
            amount: 100,
        },
    ))?;
    let block = produce_block(&db, mempool.drain_pending(1), &issuer, now())?;
    info!(
        "block {}: non-compliant transfer attempted, applied actions={}",
        block.height,
        block.actions.len()
    );
    assert_eq!(
        block.actions.len(),
        0,
        "non-compliant transfer must be rejected, not applied"
    );

    let issuer_final = db.get_account(&issuer)?.unwrap();
    let kyc_final = db.get_account(&kyc_recipient)?.unwrap();
    let non_kyc_final = db.get_account(&non_kyc_recipient)?.unwrap();
    println!(
        "final: issuer balance={} nonce={}, kyc_recipient balance={}, non_kyc_recipient balance={}",
        issuer_final.balance, issuer_final.nonce, kyc_final.balance, non_kyc_final.balance
    );
    assert_eq!(issuer_final.balance, 600);
    assert_eq!(kyc_final.balance, 400);
    assert_eq!(
        non_kyc_final.balance, 0,
        "non-KYC'd account must not receive funds"
    );

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
