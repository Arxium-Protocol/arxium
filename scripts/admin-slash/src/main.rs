// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

// ponytail: testing-only admin tool for local devnet, mirroring scripts/send-tx.
// `circuit_staking::apply_slash` is deliberately not wired to any
// `ActionPayload` variant — unreachable from RPC/mempool by construction, not
// just by convention. This is the manual/out-of-band call path until a real
// fault detector exists: it opens the node's on-disk DB directly, the same
// way `arxd` itself does, and writes the slash as one atomic batch.
//
// Requires the target node process to be stopped first — RocksDB only
// allows one writer per DB directory, so this can't run against a live node.
use anyhow::{Context, Result, bail};
use circuit_staking::{SlashReason, apply_slash};
use clap::Parser;
use std::path::PathBuf;
use xc_primitives::Address;
use xc_storage::{ArxiumDb, BlockView};

#[derive(Parser)]
struct Args {
    /// The stopped node's chain data directory (e.g.
    /// ~/.arxium/corechain/data) — not the node's --base-path, which now
    /// holds bin/config/keys shared across chains.
    #[arg(long)]
    data_path: PathBuf,

    /// Validator address to slash (bech32).
    #[arg(long)]
    validator: String,

    /// Amount to burn, capped at the validator's total staked (active + unbonding).
    #[arg(long)]
    amount: u128,

    /// "double-sign" (default) or "downtime" — stub taxonomy, cosmetic until
    /// a real fault detector exists.
    #[arg(long, default_value = "double-sign")]
    reason: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let validator = Address::parse(&args.validator).context("invalid --validator address")?;
    let reason = match args.reason.as_str() {
        "double-sign" => SlashReason::DoubleSign,
        "downtime" => SlashReason::Downtime,
        other => bail!("unknown --reason {other:?}, expected double-sign or downtime"),
    };

    let db = ArxiumDb::open(&args.data_path).context(
        "failed to open node DB — is the node still running? stop it first, RocksDB allows only one writer",
    )?;
    let tip_height = db.get_tip_height()?.unwrap_or(0);

    let sub_account = circuit_staking::stake_subaccount(&validator);
    let before = db.get_account(&sub_account)?.map(|a| a.balance).unwrap_or(0);

    let view = BlockView::new(&db);
    let (accounts, stakes) = apply_slash(&view, &validator, args.amount, reason, tip_height)?;
    db.write_batches(&[&accounts, &stakes])?;

    let after = db.get_account(&sub_account)?.map(|a| a.balance).unwrap_or(0);
    println!(
        "slashed {validator} ({reason:?}) at height {tip_height}: sub-account {sub_account} {before} -> {after}"
    );
    Ok(())
}
