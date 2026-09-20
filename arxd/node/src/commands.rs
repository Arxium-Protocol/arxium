// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The `arxd <subcommand>` handlers: key generation and inspection, pairing,
//! snapshot/prune maintenance and chain-spec introspection. Everything that
//! runs *instead of* the node; booting the node itself is `run_node` in
//! `lib.rs`.

use crate::components::new_partial;
use crate::validator;
use anyhow::{Context, Result};
use arxd_network::identity;
use xc_primitives::Address;
use xc_runtime_api::ChainRuntime;

pub(crate) fn cmd_node_key(base_path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
    let keypair = identity::load_or_generate_keypair(base_path)?;
    println!("{}", arxd_network::PeerId::from(keypair.public()));
    Ok(())
}

pub(crate) fn cmd_keys(base_path: &std::path::Path, json: bool, stake: u128) -> Result<()> {
    std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;

    let validator_key = validator::load_or_generate_key(base_path)?;
    let address = Address::from_pubkey_bytes(validator_key.verifying_key().as_bytes())?;
    let (bls_secret, bls_pubkey) = validator::load_or_generate_bls_key(base_path)?;
    let bls_hex = hex::encode(bls_pubkey.0);
    let bls_pop_hex = hex::encode(xc_bls::prove_possession(&bls_secret).0);
    let peer_id =
        arxd_network::PeerId::from(identity::load_or_generate_keypair(base_path)?.public());

    // Built from `ValidatorEntry` itself rather than hand-written JSON, so
    // the field names cannot drift from what the spec loader expects —
    // a mismatch here would produce output that looks right and silently
    // fails to register a key.
    let entry = std::collections::BTreeMap::from([(
        address.clone(),
        xc_primitives::ValidatorEntry {
            stake,
            bls_pubkey: Some(bls_hex.clone()),
            bls_pop: Some(bls_pop_hex.clone()),
        },
    )]);
    let entry_json =
        serde_json::to_string_pretty(&entry).context("failed to render the chain-spec entry")?;

    if json {
        println!("{entry_json}");
        return Ok(());
    }

    println!();
    println!("  Validator address   {address}");
    println!("  BLS finality key    {bls_hex}");
    println!("  BLS possession proof {bls_pop_hex}");
    println!("  libp2p peer ID      {peer_id}");
    println!();
    println!("  Chain-spec entry — merge into \"validators\" in the genesis spec:");
    println!();
    for line in entry_json.lines() {
        println!("    {line}");
    }
    println!();
    println!("  The validator address must appear in the chain spec's validator set,");
    println!("  or be added later with JoinValidator, or this node never produces a");
    println!("  block. Without the BLS key it can produce but never vote on finality,");
    println!("  while still counting toward the quorum it cannot help meet.");
    println!();
    Ok(())
}

pub(crate) fn cmd_validator_key(base_path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
    let key = validator::load_or_generate_key(base_path)?;
    println!(
        "{}",
        Address::from_pubkey_bytes(key.verifying_key().as_bytes())?
    );
    Ok(())
}

pub(crate) fn cmd_bls_key(base_path: &std::path::Path, qr: bool, pop: bool) -> Result<()> {
    std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
    let (secret, pubkey) = validator::load_or_generate_bls_key(base_path)?;
    if pop {
        println!("{}", hex::encode(xc_bls::prove_possession(&secret).0));
        return Ok(());
    }
    let hex_pubkey = hex::encode(pubkey.0);
    println!("{hex_pubkey}");
    if qr {
        // pubkey ‖ pop in one code: the app's JoinValidator/RegisterBlsKey
        // both need the proof of possession, and scanning twice is worse.
        let payload = format!(
            "{hex_pubkey}{}",
            hex::encode(xc_bls::prove_possession(&secret).0)
        );
        let code =
            qrcode::QrCode::new(&payload).context("failed to render BLS key as a QR code")?;
        let image = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        println!("{image}");
    }
    Ok(())
}

pub(crate) fn cmd_pair<R: ChainRuntime>(
    base_path: &std::path::Path,
    node: &str,
    token: Option<&str>,
    revoke: bool,
) -> Result<()> {
    // The pairing session this command creates lives only in this node
    // process's memory (see core/rpc's PairingStore) — printed up front
    // so a mismatch against whatever node the app's backend actually
    // talks to (NODE_RPC_URL) is obvious immediately, not after a
    // confusing "expired" report from the app minutes later.
    println!(
        "Connecting to node at {node}{}",
        if token.is_some() { " (with token)" } else { "" }
    );
    std::fs::create_dir_all(base_path).context("failed to create base-path directory")?;
    let key = validator::load_or_generate_key(base_path)?;
    let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes())
        .context("validator key produced an invalid address")?;
    R::pair(&key.to_bytes(), &sender, node, token, revoke)
}

pub(crate) fn cmd_snapshot<R: ChainRuntime>(
    base_path: &std::path::Path,
    chain: &str,
    output: &std::path::Path,
) -> Result<()> {
    // Read-only, so goes through `new_partial` like the running node
    // does rather than opening the DB by hand — same tip-signature
    // verification, same genesis-write-on-first-run behavior, so a
    // snapshot taken from data nothing else has ever booted still works.
    // `is_validator: false` (the default below) means no key material
    // gets generated just to export a checkpoint.
    let config = xc_primitives::NodeConfig {
        base_path: base_path.to_path_buf(),
        chain: chain.to_string(),
        port: 0,
        p2p_port: 0,
        bootnodes: Vec::new(),
        is_bootnode: false,
        is_validator: false,
        rpc_token: None,
        admin_token: None,
        rpc_bind: "127.0.0.1".to_string(),
        limits: xc_primitives::Limits::default(),
        snapshot_trust: None,
    };
    let components = new_partial::<R>(&config)?;
    components.db.export_checkpoint(output).with_context(|| {
        format!(
            "failed to write checkpoint to {} (must not already exist)",
            output.display()
        )
    })?;
    let tip = components.db.get_tip_height()?.unwrap_or(0);
    println!(
        "wrote checkpoint at tip height {tip} to {}",
        output.display()
    );
    Ok(())
}

pub(crate) fn cmd_prune<R: ChainRuntime>(
    base_path: &std::path::Path,
    chain: &str,
    retain_blocks: u64,
) -> Result<()> {
    let config = xc_primitives::NodeConfig {
        base_path: base_path.to_path_buf(),
        chain: chain.to_string(),
        port: 0,
        p2p_port: 0,
        bootnodes: Vec::new(),
        is_bootnode: false,
        is_validator: false,
        rpc_token: None,
        admin_token: None,
        rpc_bind: "127.0.0.1".to_string(),
        limits: xc_primitives::Limits::default(),
        snapshot_trust: None,
    };
    let components = new_partial::<R>(&config)?;
    let tip = components.db.get_tip_height()?.unwrap_or(0);
    let requested_cutoff = tip.saturating_sub(retain_blocks);
    let actual_cutoff = requested_cutoff.min(components.db.get_final_watermark()?);
    components.db.prune::<R::Payload>(requested_cutoff)?;
    println!(
        "pruned blocks and superseded validator-set snapshots below height {actual_cutoff} (tip {tip}, retain_blocks {retain_blocks})"
    );
    Ok(())
}

pub(crate) fn cmd_chain_info<R: ChainRuntime>(chain: &str, list: bool) -> Result<()> {
    if list {
        for name in R::presets().names() {
            println!("{name}");
        }
        return Ok(());
    }
    let spec_json = xc_chain_spec::resolve_chain_spec(chain, R::presets())?;
    let chain_spec = arxd_genesis::ChainSpec::parse(&spec_json)?;
    match &chain_spec {
        arxd_genesis::ChainSpec::Plain(snapshot) => {
            snapshot
                .validate()
                .context("chain spec failed validation")?;
            println!("format:         plain");
            println!("chain name:     {}", snapshot.chain_name);
            // A chain's genesis hash is block 0's state root — the state
            // actually reached at genesis, which means opening a DB.
            // Skipped here so `chain-info` stays a zero-RocksDB preview;
            // use `arx-spec-builder inspect` for the real hash. The node
            // seeds that same value into `GenesisHashKey` at genesis, so
            // `submit_execution_fault` can reject another chain's
            // artifacts.
            println!("genesis hash:   <derive with `arx-spec-builder inspect`, or boot the node>");
            println!("validators:     {}", snapshot.validators.len());
            println!("accounts:       {}", snapshot.accounts.len());
            println!("boot nodes:     {}", snapshot.boot_nodes.len());
        }
        arxd_genesis::ChainSpec::Raw(raw) => {
            println!(
                "format:         raw (format_version {})",
                raw.format_version
            );
            println!("chain name:     {}", raw.chain_name);
            println!("genesis hash:   {}", raw.state_root);
            println!("source spec:    {}", raw.source_spec_hash);
            println!("boot nodes:     {}", raw.boot_nodes.len());
            println!("entries:        {}", raw.entries.len());
        }
    }
    Ok(())
}

pub(crate) fn cmd_chain_spec<R: ChainRuntime>(chain: &str) -> Result<()> {
    let spec_json = xc_chain_spec::resolve_chain_spec(chain, R::presets())?;
    println!("{spec_json}");
    Ok(())
}
