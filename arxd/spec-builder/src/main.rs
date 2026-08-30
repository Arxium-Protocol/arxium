// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

// ponytail: standalone chain-spec CLI, mirroring scripts/admin-slash — no
// runtime/network code, just spec resolution (xc-chain-spec) and the
// Plain->Raw derivation (genesis). `arxd` (arxd/node/src/components.rs) never
// depends on this crate; it only ever loads whatever file this tool wrote,
// through the same `--chain` loader it uses for a preset name.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use genesis::ChainSpec;
use std::path::PathBuf;
use xc_chain_spec::presets::PresetRegistry;

/// CoreChain's presets, embedded independently of `arxd/node` — this crate
/// must build and produce a chain spec with zero dependency on the node
/// binary, the same way `toy-chain` proves `xc-chain-spec` has no dependency
/// on CoreChain. Kept in sync with `arxd/runtime/src/specs.rs` by hand; the two
/// crates deliberately don't share a dependency edge.
static CORECHAIN_PRESETS: PresetRegistry = PresetRegistry::new(&[
    ("devnet", include_str!("../../runtime/specs/devnet.json")),
    ("local", include_str!("../../runtime/specs/local.json")),
]);

#[derive(Parser)]
#[command(about = "Arxium chain-spec builder/inspector")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolves `--chain` (a preset name or a path to a plain chain spec)
    /// and writes it back out — as-is for a plain build, or converted to the
    /// raw representation with `--raw`. A raw build re-derives the state
    /// root from the exact same code path a node boots through
    /// (`genesis::write_plain`), so it can never drift from what booting the
    /// plain spec directly would produce.
    Build {
        /// Preset name (`devnet`, `local`) or path to a plain chain spec.
        #[arg(long)]
        chain: String,
        /// Emit the raw (encoded-entries) representation instead of the
        /// plain one.
        #[arg(long)]
        raw: bool,
        /// Destination file. Must not already exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// Prints a chain spec's summary without booting a node — chain name,
    /// format, and (for a raw spec, which carries it for free) the genesis
    /// hash. A plain spec's genesis hash isn't shown here: computing it
    /// means installing genesis state and hashing the result, which needs a
    /// RocksDB open this command deliberately avoids.
    Inspect {
        /// Preset name or path to a chain spec (plain or raw).
        #[arg(long)]
        chain: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Build { chain, raw, output } => run_build(&chain, raw, &output),
        Command::Inspect { chain } => run_inspect(&chain),
    }
}

fn run_build(chain: &str, raw: bool, output: &std::path::Path) -> Result<()> {
    if output.exists() {
        bail!("{} already exists — refusing to overwrite", output.display());
    }
    let spec_json = xc_chain_spec::resolve_chain_spec(chain, &CORECHAIN_PRESETS)?;

    let out_json = if raw {
        let raw_spec = genesis::derive_raw(&spec_json)?;
        serde_json::to_vec_pretty(&ChainSpec::Raw(raw_spec))?
    } else {
        // Already tagged `"genesis_format": "plain"` by whoever authored it;
        // round-trip through `ChainSpec` so a malformed plain spec is caught
        // here rather than at boot time.
        let spec = ChainSpec::parse(&spec_json)?;
        if !matches!(spec, ChainSpec::Plain(_)) {
            bail!("`--chain {chain}` resolved to a raw spec — build from a plain spec, or drop --raw to pass it through");
        }
        serde_json::to_vec_pretty(&spec)?
    };

    std::fs::write(output, &out_json)
        .with_context(|| format!("failed to write chain spec to {}", output.display()))?;
    println!("wrote {} chain spec to {}", if raw { "raw" } else { "plain" }, output.display());
    Ok(())
}

fn run_inspect(chain: &str) -> Result<()> {
    let spec_json = xc_chain_spec::resolve_chain_spec(chain, &CORECHAIN_PRESETS)?;
    let spec = ChainSpec::parse(&spec_json)?;
    match spec {
        ChainSpec::Plain(snapshot) => {
            snapshot.validate().context("chain spec failed validation")?;
            println!("format:      plain");
            println!("chain name:  {}", snapshot.chain_name);
            println!("validators:  {}", snapshot.validators.len());
            println!("accounts:    {}", snapshot.accounts.len());
            println!("boot nodes:  {}", snapshot.boot_nodes.len());
        }
        ChainSpec::Raw(raw) => {
            println!("format:      raw (format_version {})", raw.format_version);
            println!("chain name:  {}", raw.chain_name);
            println!("genesis hash: {}", raw.state_root);
            println!("source spec: {}", raw.source_spec_hash);
            println!("boot nodes:  {}", raw.boot_nodes.len());
            println!("entries:     {}", raw.entries.len());
        }
    }
    Ok(())
}
