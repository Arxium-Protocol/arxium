// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::presets::PresetRegistry;
use anyhow::{Context, Result};

/// Resolves a chain identifier to spec JSON text: a name the registry knows
/// is a preset, and **anything else is a file path**. No suffix or separator
/// heuristic — a bare `staging` spec file resolves correctly, and a preset
/// can never be shadowed by a same-named file.
pub fn resolve_chain_spec(raw: &str, registry: &PresetRegistry) -> Result<String> {
    if let Some(json) = registry.get(raw) {
        return Ok(json.to_owned());
    }
    std::fs::read_to_string(raw).with_context(|| {
        let names: Vec<&str> = registry.names().collect();
        let known = if names.is_empty() {
            "this binary has no built-in presets".to_string()
        } else {
            format!("known presets: {}", names.join(", "))
        };
        format!("{raw:?} is not a known preset ({known}) and could not be read as a chain spec file")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const REGISTRY: PresetRegistry = PresetRegistry::new(&[
        ("alpha", r#"{"height":0,"chain_name":"alpha","accounts":{},"validators":{},"boot_nodes":[]}"#),
        ("beta", r#"{"height":0,"chain_name":"beta","accounts":{},"validators":{},"boot_nodes":[]}"#),
    ]);

    #[test]
    fn unknown_preset_error_lists_known_presets() {
        let err = resolve_chain_spec("bogus", &REGISTRY).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("alpha"), "must list alpha: {msg}");
        assert!(msg.contains("beta"), "must list beta: {msg}");
    }

    #[test]
    fn empty_registry_error_says_no_presets_available() {
        let err = resolve_chain_spec("bogus", &PresetRegistry::EMPTY).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no built-in presets"), "must say so plainly: {msg}");
    }

    #[test]
    fn file_source_reads_spec_at_runtime() {
        let path = std::env::temp_dir().join(format!(
            "arxium-test-chain-spec-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let spec = r#"{"height":0,"chain_name":"runtime-loaded","accounts":{},"validators":{},"boot_nodes":[]}"#;
        std::fs::File::create(&path).unwrap().write_all(spec.as_bytes()).unwrap();

        let loaded =
            resolve_chain_spec(path.to_str().unwrap(), &PresetRegistry::EMPTY).expect("must read from disk");
        let snapshot: xc_primitives::Snapshot = serde_json::from_str(&loaded).unwrap();
        assert_eq!(snapshot.chain_name, "runtime-loaded");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn preset_source_resolves_by_name() {
        let alpha = resolve_chain_spec("alpha", &REGISTRY).unwrap();
        let snapshot: xc_primitives::Snapshot = serde_json::from_str(&alpha).unwrap();
        assert_eq!(snapshot.chain_name, "alpha");

        let beta = resolve_chain_spec("beta", &REGISTRY).unwrap();
        let snapshot: xc_primitives::Snapshot = serde_json::from_str(&beta).unwrap();
        assert_eq!(snapshot.chain_name, "beta");
    }

    /// Pins A.5's resolution order: registry lookup happens before any file
    /// read, so a preset name can never be shadowed by a same-named file
    /// sitting in the working directory.
    #[test]
    fn a_preset_name_is_preferred_over_a_file_of_the_same_name() {
        // A relative path literally named "alpha", sitting right where
        // `resolve_chain_spec("alpha", ..)` would look if it fell through
        // to a file read.
        std::fs::write("alpha", "not valid json").unwrap();

        let resolved = resolve_chain_spec("alpha", &REGISTRY).unwrap();
        assert!(resolved.contains("\"alpha\""));

        std::fs::remove_file("alpha").ok();
    }
}
