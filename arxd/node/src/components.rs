// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::validator;
use anyhow::{Context, Result};
use genesis::ChainSpec;
use xc_runtime_api::ChainRuntime;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use xc_mempool::Mempool;
use xc_primitives::{Address, NodeConfig};
use xc_storage::ArxiumDb;

/// Everything a node needs that does *not* require the network: genesis,
/// storage, identity, mempool. Built by `new_partial`, consumed by `run()`.
///
/// The split is not cosmetic. `Command::Snapshot` used to open the DB itself
/// and so skipped the tip-signature check `new_partial` performs; anything
/// read-only must be able to get a validated handle without spawning a P2P
/// swarm.
pub(crate) struct NodeComponents<R: ChainRuntime> {
    pub db: ArxiumDb,
    pub chain_name: String,
    pub boot_nodes: Vec<String>,
    /// The genesis state root, decoded to bytes — the chain's identity. Used
    /// as the gossip-topic suffix, so nodes on different genesis state never
    /// subscribe to each other's topics.
    ///
    /// Derived from the state actually reached at genesis, not the spec text
    /// (a `Sha256` of the JSON, as this used to be): a Plain spec and its
    /// derived Raw spec have different JSON text by construction, so hashing
    /// the text would give the same chain two different gossip topics
    /// depending on which representation booted it — silently partitioning
    /// the network the moment anyone switched. Hashing the state root instead
    /// gives both representations the same identity, since `write_raw`
    /// already guarantees they reach the same state.
    pub genesis_hash: [u8; 32],
    pub identity: Option<(Address, ed25519_dalek::SigningKey)>,
    pub bls_identity: Option<(Address, xc_bls::BlsSecretKey)>,
    pub mempool: Arc<Mutex<Mempool<R::Payload>>>,
    _runtime: PhantomData<R>,
}

/// Where this node's RocksDB lives under `base_path` — `<base_path>/<chain_name>/data`.
/// Pulled out of `new_partial` so callers that only need the data dir (e.g. the
/// `Snapshot` command) don't have to duplicate the chain-name lookup, or open
/// the DB through `new_partial`'s genesis-writing path just to find it.
pub(crate) fn chain_data_path(base_path: &std::path::Path, chain_name: &str) -> std::path::PathBuf {
    base_path.join(chain_name).join("data")
}

/// Decodes a `"0x..."`-prefixed 32-byte state root (see
/// `xc_storage::ArxiumDb::compute_state_root`) into raw bytes for use as the
/// gossip-topic suffix.
fn state_root_bytes(state_root: &str) -> Result<[u8; 32]> {
    let hex_part = state_root.strip_prefix("0x").unwrap_or(state_root);
    let bytes = hex::decode(hex_part).context("state root is not valid hex")?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("state root is {} bytes, expected 32", v.len()))
}

/// Read-only construction: genesis load, DB open, genesis write on a fresh
/// chain, tip verification, identity/mempool setup. No network, no RPC, no
/// metrics recorder, no spawned threads. Safe to call from a subcommand.
pub(crate) fn new_partial<R: ChainRuntime>(config: &NodeConfig) -> Result<NodeComponents<R>> {
    let spec_json = xc_chain_spec::resolve_chain_spec(&config.chain, R::presets())?;
    let chain_spec = ChainSpec::parse(&spec_json)?;

    let data_path = chain_data_path(&config.base_path, chain_spec.chain_name());
    let db = ArxiumDb::open(&data_path)?;

    // Both variants go through the same two functions, and only these two —
    // no other code path writes genesis state. A raw spec is validated
    // against its own declared `state_root` inside `write_raw`, so a raw
    // spec generated for a different chain (or corrupted, or stale after an
    // encoding change) is refused here rather than silently installed; see
    // `genesis::write_raw`'s doc comment.
    let (chain_name, boot_nodes, state_root) = match &chain_spec {
        ChainSpec::Plain(snapshot) => {
            let state_root = genesis::write_plain(&db, snapshot)?;
            (snapshot.chain_name.clone(), snapshot.boot_nodes.clone(), state_root)
        }
        ChainSpec::Raw(raw) => {
            genesis::write_raw(&db, raw)?;
            (raw.chain_name.clone(), raw.boot_nodes.clone(), raw.state_root.clone())
        }
    };
    let genesis_hash = state_root_bytes(&state_root)?;

    // Detect on-disk corruption/tampering before building on top of the tip:
    // a signed block whose signature no longer verifies means something is
    // wrong with this node's storage, not with the chain going forward.
    let tip_height = db.get_tip_height()?.unwrap_or(0);
    if let Some(tip_block) = db.get_block::<R::Payload>(tip_height)?
        && tip_block.signature.is_some()
    {
        tip_block
            .verify_proposer_signature()
            .context("tip block signature failed verification — on-disk corruption or tampering")?;
    }

    // Key loading stays after the DB/genesis work above, not before:
    // `load_or_generate_key`/`load_or_generate_bls_key` write a key file on
    // first run, and a node that fails genesis validation shouldn't leave
    // generated key material behind.
    //
    // Some((address, key)) if this node produces signed blocks on its turn;
    // None means it never produces — it only accepts blocks from peers.
    let identity = if config.is_validator {
        let key = validator::load_or_generate_key(&config.base_path)?;
        let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes())?;
        Some((address, key))
    } else {
        None
    };

    // Same address as the Ed25519 identity above — a validator's BLS key is
    // only meaningful once its pubkey is registered on-chain via a
    // `RegisterBlsKey` action (`arxd/node/src/payload.rs`), which is an
    // operator step, not automated here.
    let bls_identity = identity
        .as_ref()
        .map(|(address, _)| -> Result<(Address, xc_bls::BlsSecretKey)> {
            let (bls_key, _pubkey) = validator::load_or_generate_bls_key(&config.base_path)?;
            Ok((address.clone(), bls_key))
        })
        .transpose()?;

    let mempool = Arc::new(Mutex::new(Mempool::new()));

    Ok(NodeComponents {
        db,
        chain_name,
        boot_nodes,
        genesis_hash,
        identity,
        bls_identity,
        mempool,
        _runtime: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxd_runtime::{ChainBlock, CoreChainRuntime};
    use crate::produce::produce_block;
    use ed25519_dalek::SigningKey;

    fn test_config() -> NodeConfig {
        let base_path = std::env::temp_dir().join(format!(
            "arxium-test-components-{}-{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::thread::current().id(),
        ));
        NodeConfig {
            base_path,
            chain: "devnet".to_string(),
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
        let components = new_partial::<CoreChainRuntime>(&config).unwrap();
        let db = components.db;

        // Produce and sign block 1, same as a real validator would.
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        produce_block::<CoreChainRuntime>(&db, Vec::new(), 1, Some((&address, &key))).unwrap();
        drop(db);

        // Re-opening with an untampered signed tip must succeed.
        new_partial::<CoreChainRuntime>(&config).unwrap();

        // Tamper with the tip block's content in place, signature unchanged —
        // this must now be caught rather than silently built on top of.
        let db = ArxiumDb::open(&config.base_path.join("corechain").join("data")).unwrap();
        let mut tampered: ChainBlock = db.get_block(1).unwrap().unwrap();
        tampered.timestamp += 1;
        db.write_batch(&tampered).unwrap();
        drop(db);

        assert!(
            new_partial::<CoreChainRuntime>(&config).is_err(),
            "new_partial must reject a tip block whose signature no longer verifies"
        );

        std::fs::remove_dir_all(&config.base_path).ok();
    }

    /// The property that makes `new_partial` reusable by read-only
    /// subcommands: calling it twice against the same `base_path` succeeds
    /// both times, the second call seeing the chain the first one wrote —
    /// and both calls agree on the genesis hash, since it's derived from the
    /// state root rather than recomputed some other way each time.
    #[test]
    fn new_partial_is_reusable_across_calls() {
        let config = test_config();

        let first = new_partial::<CoreChainRuntime>(&config).unwrap();
        assert_eq!(first.chain_name, "corechain");
        drop(first.db);

        let second = new_partial::<CoreChainRuntime>(&config).unwrap();
        assert_eq!(second.chain_name, "corechain");
        assert_eq!(second.genesis_hash, first.genesis_hash);
        assert_eq!(second.db.get_tip_height().unwrap().unwrap_or(0), 0);

        std::fs::remove_dir_all(&config.base_path).ok();
    }

    /// Pins the ordering requirement above: a genesis spec that fails
    /// `Snapshot::validate()` must be rejected before any key material is
    /// generated on disk, or a failed boot leaves an orphaned key behind.
    #[test]
    fn new_partial_does_not_generate_keys_when_genesis_is_invalid() {
        let base_path = std::env::temp_dir().join(format!(
            "arxium-test-components-invalid-genesis-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let spec_path = base_path.join("bad-spec.json");
        std::fs::create_dir_all(&base_path).unwrap();
        std::fs::write(
            &spec_path,
            r#"{"genesis_format":"plain","height":1,"chain_name":"t","accounts":{},"validators":{},"boot_nodes":[]}"#,
        )
        .unwrap();

        let config = NodeConfig {
            base_path: base_path.clone(),
            chain: spec_path.to_string_lossy().into_owned(),
            port: 0,
            p2p_port: 0,
            bootnodes: Vec::new(),
            is_bootnode: false,
            is_validator: true,
            rpc_token: None,
            rpc_bind: "127.0.0.1".to_string(),
        };

        assert!(new_partial::<CoreChainRuntime>(&config).is_err(), "an invalid genesis spec must be rejected");
        assert!(!base_path.join("validator.key").exists(), "must not generate a key on a failed boot");

        std::fs::remove_dir_all(&base_path).ok();
    }

    /// A `genesis.artifact.json` (or any other undeclared file) sitting in
    /// the chain's data directory must never be consulted — genesis enters a
    /// node exactly one way, through `--chain`. This is the regression guard
    /// for the old artifact-discovery path, which loaded whatever sat at a
    /// magic filename with no binding to the running `--chain` at all.
    #[test]
    fn no_genesis_is_installed_from_an_undeclared_file() {
        let config = test_config();
        std::fs::create_dir_all(config.base_path.join("corechain")).unwrap();
        std::fs::write(
            config.base_path.join("corechain").join("genesis.artifact.json"),
            r#"{"not":"a chain spec"}"#,
        )
        .unwrap();

        // Must still boot normally off `--chain devnet`, ignoring the file
        // entirely — no code path reads it any more.
        let components = new_partial::<CoreChainRuntime>(&config).unwrap();
        assert_eq!(components.chain_name, "corechain");

        std::fs::remove_dir_all(&config.base_path).ok();
    }

    /// A raw chain spec derived from devnet must boot to the exact same
    /// genesis hash as devnet's plain spec — the property that makes them
    /// interchangeable representations of the same chain (and the fix for
    /// the old artifact format silently forking the gossip topic).
    #[test]
    fn plain_and_raw_devnet_produce_the_same_genesis_hash() {
        let plain_config = test_config();
        let plain = new_partial::<CoreChainRuntime>(&plain_config).unwrap();
        drop(plain.db);

        let devnet_spec = include_str!("../../runtime/specs/devnet.json");
        let raw = genesis::derive_raw(devnet_spec).unwrap();
        let raw_spec = ChainSpec::Raw(raw);
        let raw_json = serde_json::to_string(&raw_spec).unwrap();

        let raw_dir = std::env::temp_dir().join(format!(
            "arxium-test-components-raw-{}-{:?}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            std::thread::current().id(),
        ));
        let spec_path = raw_dir.join("devnet-raw.json");
        std::fs::create_dir_all(&raw_dir).unwrap();
        std::fs::write(&spec_path, &raw_json).unwrap();

        let raw_config = NodeConfig { base_path: raw_dir.clone(), chain: spec_path.to_string_lossy().into_owned(), ..test_config() };
        let raw_components = new_partial::<CoreChainRuntime>(&raw_config).unwrap();

        assert_eq!(raw_components.genesis_hash, plain.genesis_hash);

        std::fs::remove_dir_all(&plain_config.base_path).ok();
        std::fs::remove_dir_all(&raw_dir).ok();
    }
}
