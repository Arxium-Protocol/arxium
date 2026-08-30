// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use xc_primitives::Snapshot;

/// A chain spec in either representation. `Plain` is the human-authored form
/// (accounts, validators, boot nodes); `Raw` is the encoded storage entries
/// derived from it. Both arrive through `--chain` and both go through the
/// same loader (`write_plain`/`write_raw`) — there is exactly one way genesis
/// enters a node.
///
/// This lives in `genesis` rather than `xc-chain-spec` even though the
/// Plain/Raw split is itself chain-agnostic: `RawGenesis::entries` is bound to
/// CoreChain's storage layout (`xc-storage`'s CF names, key prefixes, bincode
/// struct shapes), and genericizing that (e.g. `ChainSpec<R>`) is only
/// justified once a second chain actually wants a raw variant. `core/`
/// (`xc-chain-spec`) stays the generic lookup mechanism; this crate stays the
/// concrete "what genesis state looks like for a BLS-finality CoreChain-shaped
/// chain" answer.
#[derive(Debug, Serialize)]
#[serde(tag = "genesis_format", rename_all = "snake_case")]
pub enum ChainSpec {
    Plain(Snapshot),
    Raw(RawGenesis),
}

impl ChainSpec {
    pub fn chain_name(&self) -> &str {
        match self {
            ChainSpec::Plain(snapshot) => &snapshot.chain_name,
            ChainSpec::Raw(raw) => &raw.chain_name,
        }
    }

    /// Parses a chain spec from its flat, tagged JSON form.
    ///
    /// Deliberately not a `Deserialize` impl: serde's internally-tagged enum
    /// support buffers the whole object through a private `Content` type
    /// that has no `u128`/`i128` representation, and `AccountEntry::balance`
    /// is a `u128` — an internally-tagged `#[derive(Deserialize)]` panics
    /// with "u128 is not supported" on any real balance. Parsing the tag and
    /// then the whole spec as two independent top-level `serde_json::from_str`
    /// calls instead goes through JSON's normal (unbuffered) numeric path,
    /// which handles `u128` correctly.
    pub fn parse(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Tag {
            genesis_format: String,
        }
        let tag: Tag = serde_json::from_str(json).context("chain spec is missing genesis_format")?;
        match tag.genesis_format.as_str() {
            "plain" => Ok(ChainSpec::Plain(serde_json::from_str(json).context("failed to parse plain chain spec")?)),
            "raw" => Ok(ChainSpec::Raw(serde_json::from_str(json).context("failed to parse raw chain spec")?)),
            other => bail!("unknown genesis_format {other:?}"),
        }
    }
}

/// Bumped whenever key encoding, CF layout, or any bincode struct reachable
/// from genesis state changes. A node refuses a raw spec at a version it
/// doesn't know rather than writing entries it would misread — the failure
/// mode a plain, unversioned artifact format had no way to catch.
pub const RAW_FORMAT_VERSION: u32 = 1;

/// One `(column_family, key, value)` triple, hex-encoded for JSON transport.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisEntry {
    pub cf: String,
    pub key_hex: String,
    pub value_hex: String,
}

impl From<&GenesisEntry> for (String, Vec<u8>, Vec<u8>) {
    fn from(entry: &GenesisEntry) -> Self {
        (
            entry.cf.clone(),
            hex::decode(&entry.key_hex).expect("verify_raw_entries rejects malformed hex first"),
            hex::decode(&entry.value_hex).expect("verify_raw_entries rejects malformed hex first"),
        )
    }
}

/// Encoded genesis storage — CoreChain's raw chain-spec variant. Every field
/// beyond `entries` exists because the old artifact format had none of them
/// and was unsafe as a result (see `write_raw`'s doc comment for what each
/// one closes).
#[derive(Debug, Serialize, Deserialize)]
pub struct RawGenesis {
    pub format_version: u32,
    /// Carried through so a raw spec is self-describing — `chain_data_path`
    /// works identically for both variants without needing to boot first.
    pub chain_name: String,
    /// SHA-256 of the plain spec this was derived from, recorded for human
    /// verification against a published value. Advisory only: a node never
    /// re-resolves the plain spec to check it, since shipping a raw spec
    /// alone (with no plain counterpart on hand) is the point.
    pub source_spec_hash: String,
    /// The state root a node must reach after installing `entries` — see
    /// `write_raw`.
    pub state_root: String,
    /// Carried through explicitly, same reason as `chain_name`: boot nodes
    /// are a spec-level field, never written to storage by
    /// `Snapshot::batch_entries`, so a raw spec has to carry its own copy or
    /// lose them entirely.
    pub boot_nodes: Vec<String>,
    pub entries: Vec<GenesisEntry>,
}

pub(crate) fn artifact_entries(raw: &RawGenesis) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    raw.entries.iter().map(Into::into).collect()
}
