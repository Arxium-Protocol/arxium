// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use xc_primitives::Snapshot;

pub mod presets;
pub mod source;

pub use source::resolve_chain_spec;

/// Parses `embedded_json` (the chain's own bundled genesis JSON, typically
/// `include_str!`'d by the caller) into a validated genesis `Snapshot`.
pub fn parse_snapshot(embedded_json: &str) -> Result<Snapshot> {
    let snapshot: Snapshot =
        serde_json::from_str(embedded_json).context("failed to parse embedded genesis JSON")?;
    snapshot.validate().context("genesis spec failed validation")?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A genesis spec at any height other than 0 is a config error — without
    /// `Snapshot::validate()` it would be silently written as `meta:height`.
    #[test]
    fn genesis_with_nonzero_height_is_rejected() {
        let spec = r#"{"height":1,"chain_name":"t","accounts":{},"validators":{},"boot_nodes":[]}"#;
        let err = parse_snapshot(spec).unwrap_err();
        assert!(format!("{err:#}").contains("height"), "expected a height error, got {err:?}");
    }
}
