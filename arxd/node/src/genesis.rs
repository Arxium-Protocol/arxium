use anyhow::{Context, Result};
use std::path::Path;
use xc_primitives::Snapshot;

const DEVNET_GENESIS_JSON: &str = include_str!("../specs/devnet.json");

pub fn load_or_init_snapshot(base_path: &Path) -> Result<Snapshot> {
    let snapshot_path = base_path.join("snapshots").join("snapshot-0.bin");
    let config = bincode::config::standard();

    if snapshot_path.exists() {
        let bytes = std::fs::read(&snapshot_path).context("failed to read cached snapshot file")?;
        let (snapshot, _len): (Snapshot, usize) = bincode::serde::decode_from_slice(&bytes, config)
            .context("failed to decode cached snapshot")?;
        Ok(snapshot)
    } else {
        let snapshot: Snapshot = serde_json::from_str(DEVNET_GENESIS_JSON)
            .context("failed to parse embedded devnet.json")?;

        if let Some(parent) = snapshot_path.parent() {
            std::fs::create_dir_all(parent).context("failed to create snapshots directory")?;
        }
        let encoded = bincode::serde::encode_to_vec(&snapshot, config)
            .context("failed to encode snapshot to bincode")?;
        std::fs::write(&snapshot_path, encoded).context("failed to write snapshot cache")?;

        Ok(snapshot)
    }
}
