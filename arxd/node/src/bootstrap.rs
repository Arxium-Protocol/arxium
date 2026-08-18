use crate::payload::{ActionPayload, ChainBlock, dispatch};
use anyhow::{Context, Result};
use tracing::info;
use xc_executor::{BlockUpdates, execute_actions};
use xc_primitives::{NodeConfig, Snapshot};
use xc_storage::ArxiumDb;

const DEVNET_GENESIS_JSON: &str = include_str!("../specs/devnet.json");

/// Opens storage and, on a fresh chain, writes the genesis snapshot and block 0.
/// Returns the snapshot too, since the produce loop needs the validator set
/// for round-robin scheduling.
pub(crate) fn bootstrap(config: &NodeConfig) -> Result<(ArxiumDb, Snapshot)> {
    let snapshot = xc_genesis::load_or_init_snapshot(&config.base_path, DEVNET_GENESIS_JSON)?;
    let db = ArxiumDb::open(&config.base_path.join("data"))?;

    if !db.is_initialized()? {
        info!(
            "writing genesis snapshot: chain={} validators={} accounts={}",
            snapshot.chain_name,
            snapshot.validators.len(),
            snapshot.accounts.len()
        );
        db.write_batch(&snapshot)?;
    }

    if db.get_block::<ActionPayload>(0)?.is_none() {
        // Fixed timestamp, not `now_secs()` — every node bootstraps its own
        // copy of genesis independently, and gossiped blocks get checked
        // against local tip's hash, so genesis must hash identically
        // everywhere or block 1 from any peer fails the parent-hash check
        // before it's even out of the gate.
        let genesis_block: ChainBlock = xc_primitives::Block::genesis(0);
        let (_, genesis_updates, _, _, _, _) = execute_actions(
            &db,
            genesis_block.actions.clone(),
            &[],
            BlockUpdates::default(),
            |action, lookup, stake_lookup, validator_masters_lookup, validators| {
                dispatch(
                    action,
                    lookup,
                    stake_lookup,
                    validator_masters_lookup,
                    validators,
                    0,
                    &|_, _| Ok(false),
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
        let db = ArxiumDb::open(&config.base_path.join("data")).unwrap();
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
