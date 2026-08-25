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

    // The cache is derived data — the embedded JSON is the source of truth —
    // so a cache this binary cannot read is a reason to regenerate it, never a
    // reason to refuse to start.
    //
    // This is not hypothetical: bincode is not self-describing, so adding a
    // field to any type inside `Snapshot` (as `ValidatorEntry.bls_pubkey` did)
    // changes the layout, and `#[serde(default)]` cannot rescue a byte stream
    // that simply ends early. Without this fallback every upgrading node would
    // fail to boot on a cache written by the previous binary, with
    // `UnexpectedEnd` and nothing pointing at the cause.
    if snapshot_path.exists() {
        match std::fs::read(&snapshot_path)
            .context("failed to read cached snapshot file")
            .and_then(|bytes| {
                bincode::serde::decode_from_slice::<Snapshot, _>(&bytes, config)
                    .context("failed to decode cached snapshot")
            }) {
            Ok((snapshot, _len)) => return Ok(snapshot),
            Err(err) => {
                tracing::warn!(
                    "cached genesis snapshot at {} is unreadable ({err:#}) — regenerating it \
                     from the embedded chain spec. Expected after an upgrade that changed the \
                     snapshot's shape; the embedded spec is authoritative either way.",
                    snapshot_path.display(),
                );
            }
        }
    }

    {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"{
        "height": 0,
        "chain_name": "test-chain",
        "accounts": {},
        "validators": {},
        "boot_nodes": []
    }"#;

    /// A cache this binary cannot decode must be regenerated, not fatal.
    /// Adding a field to any type inside `Snapshot` changes the bincode
    /// layout, and bincode is not self-describing — so without this, every
    /// node upgrading across such a change fails to boot on the cache its
    /// previous binary wrote.
    #[test]
    fn an_unreadable_snapshot_cache_is_regenerated_rather_than_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-genesis-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let cache = dir.join("snapshots").join("snapshot-0.bin");
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();

        // Truncated bincode — exactly the `UnexpectedEnd` shape a layout
        // change produces.
        std::fs::write(&cache, [0x01, 0x02, 0x03]).unwrap();

        let snapshot = load_or_init_snapshot(&dir, SPEC).expect("must recover, not fail");
        assert_eq!(snapshot.chain_name, "test-chain");

        // And the cache is rewritten, so the next boot reads it cleanly.
        let reloaded = load_or_init_snapshot(&dir, SPEC).expect("cache must be usable now");
        assert_eq!(reloaded.chain_name, "test-chain");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
