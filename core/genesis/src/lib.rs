// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::path::Path;
use xc_primitives::Snapshot;

/// Loads the genesis `Snapshot` from a per-node bincode cache, or parses
/// `embedded_json` (the chain's own bundled genesis JSON, typically
/// `include_str!`'d by the caller) and writes the cache on first boot.
/// The embedded JSON itself is chain-specific (which accounts/validators
/// exist at genesis); this function only owns the generic cache-or-parse
/// mechanics.
pub fn load_or_init_snapshot(base_path: &Path, embedded_json: &str) -> Result<Snapshot> {
    let snapshot_path = base_path.join("snapshots").join("snapshot-0.bin");
    let config = bincode::config::standard();

    if snapshot_path.exists() {
        let bytes = std::fs::read(&snapshot_path).context("failed to read cached snapshot file")?;
        let (snapshot, _len): (Snapshot, usize) = bincode::serde::decode_from_slice(&bytes, config)
            .context("failed to decode cached snapshot")?;
        Ok(snapshot)
    } else {
        let snapshot: Snapshot =
            serde_json::from_str(embedded_json).context("failed to parse embedded genesis JSON")?;

        if let Some(parent) = snapshot_path.parent() {
            std::fs::create_dir_all(parent).context("failed to create snapshots directory")?;
        }
        let encoded = bincode::serde::encode_to_vec(&snapshot, config)
            .context("failed to encode snapshot to bincode")?;
        std::fs::write(&snapshot_path, encoded).context("failed to write snapshot cache")?;

        Ok(snapshot)
    }
}
