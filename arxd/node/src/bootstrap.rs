// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::payload::{ActionPayload, ChainBlock, dispatch};
use anyhow::{Context, Result};
use tracing::{info, warn};
use xc_executor::{BlockUpdates, execute_actions};
use xc_primitives::{NodeConfig, Snapshot};
use xc_storage::{ArxiumDb, BlsKeyRegistration};

const DEVNET_GENESIS_JSON: &str = include_str!("../specs/devnet.json");

/// Where this node's RocksDB lives under `base_path` — `<base_path>/<chain_name>/data`.
/// Pulled out of `bootstrap` so callers that only need the data dir (e.g. the
/// `Snapshot` command) don't have to duplicate the chain-name lookup, or open
/// the DB through `bootstrap`'s genesis-writing path just to find it.
pub(crate) fn chain_data_path(base_path: &std::path::Path) -> Result<std::path::PathBuf> {
    // Peeking chain_name out of the embedded JSON up front (rather than
    // waiting for load_or_init_snapshot's full Snapshot) lets us scope both
    // the snapshot cache and the RocksDB dir under <base_path>/<chain_name>/
    // before either is touched — bin/config/keys stay common across chains
    // while each chain, including future spoke chains, gets its own
    // subfolder under the same base_path.
    let chain_name = serde_json::from_str::<serde_json::Value>(DEVNET_GENESIS_JSON)
        .ok()
        .and_then(|v| v.get("chain_name")?.as_str().map(str::to_string))
        .context("embedded genesis JSON is missing chain_name")?;
    Ok(base_path.join(&chain_name).join("data"))
}

/// Opens storage and, on a fresh chain, writes the genesis snapshot and block 0.
/// Returns the snapshot too, since the produce loop needs the validator set
/// for round-robin scheduling.
pub(crate) fn bootstrap(config: &NodeConfig) -> Result<(ArxiumDb, Snapshot)> {
    let data_path = chain_data_path(&config.base_path)?;
    let chain_path = data_path
        .parent()
        .expect("chain_data_path always returns <base_path>/<chain_name>/data")
        .to_path_buf();

    let snapshot = xc_genesis::load_or_init_snapshot(&chain_path, DEVNET_GENESIS_JSON)?;
    let db = ArxiumDb::open(&data_path)?;

    if !db.is_initialized()? {
        info!(
            "writing genesis snapshot: chain={} validators={} accounts={}",
            snapshot.chain_name,
            snapshot.validators.len(),
            snapshot.accounts.len()
        );
        db.write_batch(&snapshot)?;

        // Genesis validators never run `JoinValidator`, so their BLS keys have
        // to be registered here or they enter the set unable to vote — the
        // chain then produces blocks forever and finalizes nothing. Same job
        // as `session.keys` in a Substrate genesis config.
        for (address, entry) in &snapshot.validators {
            let Some(hex_pubkey) = &entry.bls_pubkey else {
                warn!(
                    "genesis validator {address} has no bls_pubkey in the chain spec — it \
                     cannot vote on finality, and counts toward the quorum it cannot help \
                     meet. Register one with a RegisterBlsKey action, or add it to the spec \
                     before launching a new chain. See GET /finality."
                );
                continue;
            };
            let bytes: [u8; 48] = hex::decode(hex_pubkey)
                .ok()
                .and_then(|b| b.try_into().ok())
                .with_context(|| {
                    format!("genesis validator {address} has a malformed bls_pubkey")
                })?;
            blst::min_pk::PublicKey::from_bytes(&bytes)
                .and_then(|pk| pk.validate())
                .map_err(|_| anyhow::anyhow!("genesis validator {address} has an invalid BLS key"))?;
            db.write_batch(&BlsKeyRegistration {
                address: address.clone(),
                pubkey: xc_bls::BlsPublicKey(bytes),
            })?;
            info!("registered genesis BLS finality key for {address}");
        }
    }

    if db.get_block::<ActionPayload>(0)?.is_none() {
        // Fixed timestamp, not `now_secs()` — every node bootstraps its own
        // copy of genesis independently, and gossiped blocks get checked
        // against local tip's hash, so genesis must hash identically
        // everywhere or block 1 from any peer fails the parent-hash check
        // before it's even out of the gate.
        let genesis_block: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _, _, _, _, _) = execute_actions(
            &db,
            genesis_block.actions.clone(),
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
                    &|_, _| Ok(false),
                    &|pk: &xc_bls::BlsPublicKey| db.bls_pubkey_owner(pk),
                )
            },
        )?;
        db.write_batches(&[&genesis_updates, &genesis_block])?;
        info!("wrote genesis block: {:?}", genesis_block);
    }

    // Detect on-disk corruption/tampering before building on top of the tip:
    // a signed block whose signature no longer verifies means something is
    // wrong with this node's storage, not with the chain going forward.
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    if let Some(tip_block) = db.get_block::<ActionPayload>(tip_height)?
        && tip_block.signature.is_some()
    {
        tip_block
            .verify_proposer_signature()
            .context("tip block signature failed verification — on-disk corruption or tampering")?;
    }

    Ok((db, snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::produce::produce_block;
    use ed25519_dalek::SigningKey;
    use xc_primitives::Address;

    fn test_config() -> NodeConfig {
        let base_path = std::env::temp_dir().join(format!(
            "arxium-test-bootstrap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        NodeConfig {
            base_path,
            port: 0,
            p2p_port: 0,
            bootnodes: Vec::new(),
            is_bootnode: false,
            is_validator: false,
            rpc_token: None,
            rpc_bind: "127.0.0.1".to_string(),
        }
    }

    #[test]
    fn bootstrap_rejects_tampered_tip_block() {
        let config = test_config();

        // First boot: writes genesis (unsigned, so nothing to verify yet).
        let (db, _snapshot) = bootstrap(&config).unwrap();

        // Produce and sign block 1, same as a real validator would.
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        produce_block(&db, Vec::new(), 1, Some((&address, &key))).unwrap();
        drop(db);

        // Re-opening with an untampered signed tip must succeed.
        bootstrap(&config).unwrap();

        // Tamper with the tip block's content in place, signature unchanged —
        // this must now be caught rather than silently built on top of.
        let db = ArxiumDb::open(&config.base_path.join("corechain").join("data")).unwrap();
        let mut tampered: ChainBlock = db.get_block(1).unwrap().unwrap();
        tampered.timestamp += 1;
        db.write_batch(&tampered).unwrap();
        drop(db);

        assert!(
            bootstrap(&config).is_err(),
            "bootstrap must reject a tip block whose signature no longer verifies"
        );

        std::fs::remove_dir_all(&config.base_path).ok();
    }
}
