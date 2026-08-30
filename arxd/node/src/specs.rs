// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use xc_chain_spec::presets::PresetRegistry;

/// CoreChain's built-in genesis presets. Embedded via `include_str!` so a
/// downloaded `arxd` runs `--chain devnet` with no files on disk; anything
/// else is `--chain <path>`, which needs no rebuild. See
/// `xc_chain_spec::presets::PresetRegistry`'s doc comment for the full
/// embed-vs-ship rationale.
pub static CORECHAIN_PRESETS: PresetRegistry = PresetRegistry::new(&[
    ("devnet", include_str!("../specs/devnet.json")),
    ("local", include_str!("../specs/local.json")),
]);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registered preset must parse as a `ChainSpec` and pass
    /// `Snapshot::validate()` — catches a broken spec at CI time rather than
    /// at an operator's first boot.
    #[test]
    fn corechain_presets_all_resolve_and_validate() {
        for name in CORECHAIN_PRESETS.names() {
            let json = CORECHAIN_PRESETS.get(name).unwrap();
            let spec = genesis::ChainSpec::parse(json).unwrap_or_else(|e| panic!("preset {name:?} failed to parse: {e}"));
            let genesis::ChainSpec::Plain(snapshot) = &spec else {
                panic!("preset {name:?} must be a plain spec");
            };
            snapshot.validate().unwrap_or_else(|e| panic!("preset {name:?} failed validation: {e}"));
        }
    }
}
