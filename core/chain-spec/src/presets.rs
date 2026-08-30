// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

/// A chain's built-in genesis presets: name -> spec JSON text. Each chain
/// binary declares its own; `core/` owns the lookup mechanism and never a
/// specific chain's genesis data — CoreChain's specs live in `arxd/node`,
/// toy-chain's in `examples/toy-chain`.
///
/// `&'static` because every real registry is built from `include_str!` at
/// the chain binary's own call site, keeping the embedded-spec property (a
/// self-contained binary that runs with no files on disk) while leaving
/// `core/` free of any chain's data.
///
/// CoreChain's official presets (`devnet`, `local`) are embedded in `arxd`
/// this way, so a downloaded binary runs with no files on disk and cannot be
/// broken by missing installer state. Every other chain — staging nets,
/// Spoke Chains, an operator's own network — uses `--chain <path>`, which
/// needs no rebuild.
pub struct PresetRegistry {
    presets: &'static [(&'static str, &'static str)],
}

impl PresetRegistry {
    /// A chain with no built-in presets — `--chain <path>` only. The right
    /// default for a tool (or a Spoke Chain operator) that has no
    /// CoreChain-style official network of its own to embed.
    pub const EMPTY: Self = Self { presets: &[] };

    pub const fn new(presets: &'static [(&'static str, &'static str)]) -> Self {
        Self { presets }
    }

    pub fn get(&self, name: &str) -> Option<&'static str> {
        self.presets.iter().find(|(n, _)| *n == name).map(|(_, json)| *json)
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.presets.iter().map(|(n, _)| *n)
    }
}
