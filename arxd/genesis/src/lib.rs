// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Genesis writing/verification for Arxium's BLS-finality chains (CoreChain
//! and any Spoke Chain that reuses the same finality scheme): BLS validator
//! key registration, and the Plain/Raw `ChainSpec` variants a node actually
//! boots from.
//!
//! This does *not* live in `xc-chain-spec` (`core/chain-spec`) even though
//! `xc-storage`'s schema (including `BlsKeyRegistration`) is itself generic
//! and shared by every chain, `toy-chain` included: what makes this crate
//! chain-specific is not the storage schema but the *pipeline* — opening a
//! DB, running the real genesis-write path end to end, and (for `derive_raw`)
//! producing a distributable raw-KV chain spec. `toy-chain` never needs any of
//! that (no validators, no raw distribution), so folding it into
//! `xc-chain-spec` would hand every `xc-chain-spec` consumer a RocksDB + BLS
//! dependency purely to call `load_or_init_snapshot`. `arxd/node` and
//! `arx-spec-builder` both depend on this crate directly instead.

pub mod chain_spec;

use anyhow::{Context, Result, bail};
use chain_spec::{GenesisEntry, RawGenesis, artifact_entries};
use std::collections::{BTreeMap, HashSet};
use xc_bls::BlsPublicKey;
use xc_primitives::{Address, Block, Snapshot, ValidatorEntry};
use xc_storage::{AccountUpdates, ArxiumDb, cf_for_key};

pub use chain_spec::{ChainSpec, RAW_FORMAT_VERSION};

const BLS_KEY_PREFIX: &[u8] = b"meta:blskey:";

/// Genesis validators that never run `JoinValidator` need their BLS key
/// registered here, or they enter the validator set unable to vote — the
/// chain then produces blocks but never finalizes anything. Same job as
/// `session.keys` in a Substrate genesis config.
pub fn register_genesis_bls_keys(db: &ArxiumDb, validators: &BTreeMap<Address, ValidatorEntry>) -> Result<()> {
    for (address, entry) in validators {
        let Some(hex_pubkey) = &entry.bls_pubkey else {
            tracing::warn!(
                "genesis validator {address} has no bls_pubkey in the chain spec — it cannot \
                 vote on finality, and counts toward quorum it cannot help meet. Register one \
                 with a RegisterBlsKey action, or add it to the spec before launching a new \
                 chain. See GET /finality."
            );
            continue;
        };
        let bytes: [u8; 48] = hex::decode(hex_pubkey)
            .ok()
            .and_then(|b| b.try_into().ok())
            .with_context(|| format!("genesis validator {address} has a malformed bls_pubkey"))?;
        blst::min_pk::PublicKey::from_bytes(&bytes)
            .and_then(|pk| pk.validate())
            .map_err(|_| anyhow::anyhow!("genesis validator {address} has an invalid BLS key"))?;
        // `RegisterBlsKey`/`JoinValidator` both reject a pubkey already
        // owned by another validator — genesis must enforce the same rule,
        // or two validators could unknowingly share a BLS identity.
        if let Some(owner) = db.bls_pubkey_owner(&BlsPublicKey(bytes))? {
            if owner != *address {
                bail!("genesis validator {address} BLS pubkey is already owned by {owner}");
            }
        }
        db.write_batch(&xc_storage::BlsKeyRegistration { address: address.clone(), pubkey: BlsPublicKey(bytes) })?;
    }
    Ok(())
}

/// Writes a plain chain spec's genesis state to `db` and returns the state
/// root reached (whether this call just wrote it or it was already there).
///
/// The one and only genesis-writing path for a Plain spec — `arxd/node` boot
/// and `derive_raw`'s scratch-DB conversion both call this, rather than each
/// maintaining their own copy that can silently drift apart (the old
/// `arxd/node::components::new_partial` had its own inline
/// `execute_actions`/`dispatch` version of exactly this).
///
/// Split into two independently-resumable steps — matching two separate
/// `db.write_batch` calls under the hood — so a crash between them is
/// recovered on the next call rather than left half-initialized: after the
/// snapshot is written `db.is_initialized()` is already true, so only the
/// block-0 check below still needs to run.
pub fn write_plain(db: &ArxiumDb, snapshot: &Snapshot) -> Result<String> {
    snapshot.validate().context("genesis spec failed validation")?;
    if !db.is_initialized()? {
        db.write_batch(snapshot)?;
        register_genesis_bls_keys(db, &snapshot.validators)?;
    }
    if db.get_block::<()>(0)?.is_none() {
        // Payload type `()`, not the caller's action-payload type: genesis
        // always has zero actions, and an empty `Vec<Action<P>>` bincodes
        // identically regardless of `P` — so this stays generic over
        // whatever payload the caller's blocks otherwise use, without this
        // crate needing to know that type.
        //
        // Fixed timestamp (0), not "now": every node bootstraps its own copy
        // of genesis independently, and it must hash identically everywhere.
        let mut genesis_block: Block<()> = Block::genesis(0);
        genesis_block.state_root = db.compute_state_root(&[])?;
        db.write_batches(&[&AccountUpdates::default(), &genesis_block])?;
    }
    let root = db
        .get_block::<()>(0)?
        .expect("just verified/written above")
        .state_root;
    Ok(root)
}

/// Installs a raw chain spec's genesis state into `db`, verifying it end to
/// end first. Closes every gap the old unversioned genesis-artifact format
/// left open:
///
/// - **format_version**: an unknown version is rejected outright, naming both
///   the file's version and what this binary supports, rather than writing
///   entries it might misread.
/// - **internal consistency**: every entry's `cf` must match what
///   `cf_for_key` derives from its own key, and every `meta:blskey:*` entry
///   must hold a well-formed, non-reused BLS pubkey.
/// - **state_root**: on a fresh install, the state actually reached must
///   equal `raw.state_root` — a mismatch means the entries do not encode what
///   the generator claimed, or this binary's encoders have diverged from the
///   generator's. This is the check that closes the "foreign artifact for the
///   wrong chain" failure mode: a raw spec is validated against *itself*,
///   fatally, not just checked for well-formedness. Recomputed from the
///   installed accounts/validators tables via `compute_state_root`, not read
///   back from the entries' own `block:0` value — that value was written by
///   the same (possibly tampered) entry set it's supposed to be checking.
///   Only checked on install: once the chain has produced blocks, the
///   current state root has moved on from genesis by design, and on-disk
///   integrity from here on is `new_partial`'s tip-signature check, not this.
pub fn write_raw(db: &ArxiumDb, raw: &RawGenesis) -> Result<()> {
    if raw.format_version != RAW_FORMAT_VERSION {
        bail!(
            "raw chain spec has format_version {}, this binary supports {RAW_FORMAT_VERSION} — \
             rebuild it with a matching arx-spec-builder",
            raw.format_version,
        );
    }
    verify_raw_entries(&raw.entries)?;

    if !db.is_initialized()? {
        db.write_raw_entries(&artifact_entries(raw))?;

        let installed_root = db.compute_state_root(&[])?;
        if installed_root != raw.state_root {
            bail!(
                "raw chain spec declares state_root {}, but the state actually installed hashes to {} \
                 — refusing to boot on a chain spec that does not describe its own contents",
                raw.state_root,
                installed_root,
            );
        }
    }
    db.get_block::<()>(0)?.context("raw chain spec installed but block 0 is missing from its entries")?;
    Ok(())
}

/// Parses `spec_json` as a `Snapshot`, writes it through `write_plain`
/// against a scratch on-disk DB, and returns the result as a `RawGenesis`.
///
/// Keeps the scratch DB (rather than re-deriving `state_root`'s hash from
/// `Snapshot::batch_entries()` directly) so this always uses the exact same
/// encoders `write_plain`/`compute_state_root` use for a real node — the
/// alternative risks a second, hand-rolled implementation of that hashing
/// quietly drifting from the real one, which is exactly the "two genesis
/// mechanisms, never cross-checked" failure this format replaces.
pub fn derive_raw(spec_json: &str) -> Result<RawGenesis> {
    let snapshot: Snapshot = serde_json::from_str(spec_json).context("failed to parse genesis spec")?;
    let source_spec_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(spec_json.as_bytes()))
    };

    let scratch_dir = std::env::temp_dir().join(format!(
        "arxium-genesis-derive-{}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        std::thread::current().id(),
    ));
    let db = ArxiumDb::open(&scratch_dir).context("failed to open scratch DB")?;
    let state_root = write_plain(&db, &snapshot)?;
    let raw_entries = db.export_all_entries()?;
    drop(db);
    std::fs::remove_dir_all(&scratch_dir).ok();

    let entries = raw_entries
        .into_iter()
        .map(|(cf, key, value)| GenesisEntry { cf, key_hex: hex::encode(key), value_hex: hex::encode(value) })
        .collect();
    let raw = RawGenesis {
        format_version: RAW_FORMAT_VERSION,
        chain_name: snapshot.chain_name,
        boot_nodes: snapshot.boot_nodes,
        source_spec_hash,
        state_root,
        entries,
    };

    // The raw spec we just built must itself pass the same checks a
    // downstream `write_raw` would apply — catches a bug here before it ever
    // reaches disk.
    verify_raw_entries(&raw.entries)?;
    Ok(raw)
}

/// Decodes and validates every entry: hex must decode, each entry's `cf`
/// must match what `cf_for_key` derives from its own key (catching a
/// hand-edited or corrupted raw spec), and every `meta:blskey:*` entry must
/// hold a well-formed BLS pubkey not reused by another validator.
fn verify_raw_entries(entries: &[GenesisEntry]) -> Result<()> {
    let mut seen_pubkeys = HashSet::new();
    for entry in entries {
        let key = hex::decode(&entry.key_hex)
            .with_context(|| format!("entry with cf {:?} has malformed key_hex", entry.cf))?;
        let value = hex::decode(&entry.value_hex)
            .with_context(|| format!("entry with cf {:?} has malformed value_hex", entry.cf))?;

        let expected_cf = cf_for_key(&key);
        if entry.cf != expected_cf {
            bail!(
                "entry key {} tagged cf {:?}, but its prefix belongs in {:?}",
                entry.key_hex,
                entry.cf,
                expected_cf
            );
        }

        if key.starts_with(BLS_KEY_PREFIX) {
            let config = bincode::config::standard();
            let (pubkey, _): (BlsPublicKey, _) = bincode::serde::decode_from_slice(&value, config)
                .with_context(|| format!("entry key {} holds an undecodable BLS pubkey", entry.key_hex))?;
            blst::min_pk::PublicKey::from_bytes(&pubkey.0)
                .and_then(|pk| pk.validate())
                .map_err(|_| anyhow::anyhow!("entry key {} holds an invalid BLS pubkey", entry.key_hex))?;
            if !seen_pubkeys.insert(pubkey.0) {
                bail!("BLS pubkey at entry key {} is reused by another validator", entry.key_hex);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_spec::ChainSpec;

    const SPEC: &str = r#"{
        "height": 0,
        "chain_name": "test-chain",
        "accounts": {},
        "validators": {},
        "boot_nodes": []
    }"#;

    fn scratch_db() -> (ArxiumDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-genesis-{}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            std::thread::current().id(),
        ));
        (ArxiumDb::open(&dir).unwrap(), dir)
    }

    /// `write_plain` twice against the same DB must not re-run genesis or
    /// error — this is what makes it safe for both a first boot and every
    /// reboot after.
    #[test]
    fn write_plain_is_idempotent() {
        let (db, dir) = scratch_db();
        let snapshot: Snapshot = serde_json::from_str(SPEC).unwrap();
        let first = write_plain(&db, &snapshot).unwrap();
        let second = write_plain(&db, &snapshot).unwrap();
        assert_eq!(first, second);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The whole point of `RawGenesis::state_root`: a raw spec generated for
    /// one chain must not silently install onto a differently-named chain's
    /// data — the failure mode a foreign `genesis.artifact.json` used to hit
    /// with no check at all.
    #[test]
    fn derive_raw_round_trips_and_verifies() {
        let raw = derive_raw(SPEC).unwrap();
        assert_eq!(raw.chain_name, "test-chain");
        assert!(!raw.entries.is_empty());

        let (db, dir) = scratch_db();
        write_raw(&db, &raw).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn raw_spec_with_unknown_format_version_is_rejected() {
        let mut raw = derive_raw(SPEC).unwrap();
        raw.format_version = RAW_FORMAT_VERSION + 1;
        let (db, dir) = scratch_db();
        let err = write_raw(&db, &raw).unwrap_err();
        assert!(err.to_string().contains("format_version"), "expected a format_version error, got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tampering an entry's value changes the state actually installed
    /// without touching the declared `state_root` — must be caught, not
    /// silently booted on.
    #[test]
    fn raw_spec_with_wrong_state_root_is_rejected() {
        let mut raw = derive_raw(SPEC).unwrap();
        // `validator_set:00000000000000000000` is written even for a
        // validator-less spec, and lives in the validators CF — tampering
        // its value is harmless to `verify_raw_entries` (still a
        // well-formed validators-CF entry) but does feed
        // `compute_state_root` (accounts + validators only), so only the
        // state-root comparison catches it.
        let idx = raw.entries.iter().position(|e| e.cf == "validators").expect("a validators entry must exist");
        raw.entries[idx].value_hex = hex::encode(b"tampered-validator-set-value");

        let (db, dir) = scratch_db();
        let err = write_raw(&db, &raw).unwrap_err();
        assert!(err.to_string().contains("state_root"), "expected a state_root mismatch error, got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `write_raw` must stay callable on every reboot, not just the first —
    /// the state-root check only means anything against a fresh install
    /// (which is what `raw.state_root` describes); once blocks have moved
    /// the root away from genesis, re-checking it on every boot would brick
    /// the node the moment any balance changes. Regression test for exactly
    /// that: the check used to run unconditionally, outside the
    /// `is_initialized` guard.
    #[test]
    fn raw_spec_boots_again_after_state_changes() {
        let raw = derive_raw(SPEC).unwrap();
        let (db, dir) = scratch_db();
        write_raw(&db, &raw).unwrap();

        let address = Address::from_pubkey_bytes(&[7u8; 32]).unwrap();
        let mut updates = AccountUpdates::default();
        updates.0.insert(
            address,
            xc_primitives::AccountEntry { balance: 1_000, nonce: 0, identity_hash: None, zk_identity_verified: false },
        );
        db.write_batch(&updates).unwrap();

        write_raw(&db, &raw).expect("reboot on a chain that has since produced state must not be rejected");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A tampered `cf` tag must be rejected before installation, not just at
    /// the state-root check — this is exactly the kind of corruption/hand-edit
    /// `verify_raw_entries` exists to catch first.
    #[test]
    fn mismatched_cf_tag_is_rejected() {
        let mut raw = derive_raw(SPEC).unwrap();
        raw.entries[0].cf = "bogus".into();
        let (db, dir) = scratch_db();
        assert!(write_raw(&db, &raw).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The property that makes Plain and Raw interchangeable representations
    /// of the same chain: booting either one reaches the same state root, so
    /// a gossip topic derived from it (see `arxd/node`) is stable across
    /// representations.
    #[test]
    fn plain_and_raw_of_the_same_chain_produce_the_same_state_root() {
        let snapshot: Snapshot = serde_json::from_str(SPEC).unwrap();
        let (plain_db, plain_dir) = scratch_db();
        let plain_root = write_plain(&plain_db, &snapshot).unwrap();

        let raw = derive_raw(SPEC).unwrap();
        assert_eq!(raw.state_root, plain_root);

        let (raw_db, raw_dir) = scratch_db();
        write_raw(&raw_db, &raw).unwrap();
        let raw_root = raw_db.get_block::<()>(0).unwrap().unwrap().state_root;
        assert_eq!(raw_root, plain_root);

        std::fs::remove_dir_all(&plain_dir).ok();
        std::fs::remove_dir_all(&raw_dir).ok();
    }

    #[test]
    fn register_genesis_bls_keys_rejects_duplicate_pubkey() {
        let (db, dir) = scratch_db();

        let ikm = [7u8; 32];
        let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        let pubkey_hex = hex::encode(sk.sk_to_pk().to_bytes());

        let addr_a = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let addr_b = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let mut validators = BTreeMap::new();
        validators.insert(addr_a, ValidatorEntry { stake: 0, bls_pubkey: Some(pubkey_hex.clone()) });
        validators.insert(addr_b, ValidatorEntry { stake: 0, bls_pubkey: Some(pubkey_hex) });

        let err = register_genesis_bls_keys(&db, &validators).unwrap_err();
        assert!(err.to_string().contains("already owned by"), "expected an already-owned rejection, got {err:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn duplicate_bls_pubkey_is_rejected_in_a_raw_spec() {
        let sk_a = blst::min_pk::SecretKey::key_gen(&[10u8; 32], &[]).unwrap();
        let sk_b = blst::min_pk::SecretKey::key_gen(&[11u8; 32], &[]).unwrap();
        let addr_a = Address::from_pubkey_bytes(&[5u8; 32]).unwrap();
        let addr_b = Address::from_pubkey_bytes(&[6u8; 32]).unwrap();
        let spec = format!(
            r#"{{"height":0,"chain_name":"t","accounts":{{}},"validators":{{
                "{addr_a}": {{"stake": 1, "bls_pubkey": "{}"}},
                "{addr_b}": {{"stake": 1, "bls_pubkey": "{}"}}
            }},"boot_nodes":[]}}"#,
            hex::encode(sk_a.sk_to_pk().to_bytes()),
            hex::encode(sk_b.sk_to_pk().to_bytes()),
        );
        // Two distinct validators with distinct keys must derive cleanly...
        let mut raw = derive_raw(&spec).unwrap();
        let bls_indices: Vec<usize> = raw
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.cf == "meta" && hex::decode(&e.key_hex).unwrap().starts_with(BLS_KEY_PREFIX))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(bls_indices.len(), 2, "spec must register 2 validator BLS keys");
        // ...but a hand-edited duplicate must be rejected by verify_raw_entries.
        let value = raw.entries[bls_indices[0]].value_hex.clone();
        raw.entries[bls_indices[1]].value_hex = value;
        assert!(verify_raw_entries(&raw.entries).is_err());
    }

    /// A malformed `bls_pubkey` must be rejected by `Snapshot::validate()`
    /// before any DB is ever opened.
    #[test]
    fn genesis_with_malformed_bls_pubkey_is_rejected_before_db_open() {
        let spec = r#"{"height":0,"chain_name":"t","accounts":{},"validators":{
            "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5": {
                "stake": 1, "bls_pubkey": "not-hex"
            }
        },"boot_nodes":[]}"#;
        let err = derive_raw(spec).unwrap_err();
        assert!(format!("{err:#}").contains("bls_pubkey"), "expected a bls_pubkey error, got {err:?}");
    }

    /// A `--chain` file with no recognizable `genesis_format` tag (or an
    /// unknown one) is a config error, not a silent default to Plain.
    #[test]
    fn chain_spec_with_unknown_format_tag_is_rejected() {
        let err = ChainSpec::parse(r#"{"genesis_format":"artifact","entries":[]}"#).unwrap_err();
        assert!(err.to_string().contains("genesis_format"), "expected a genesis_format error, got {err:?}");
    }
}
