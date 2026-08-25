// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::path::Path;
use tracing::info;
use xc_bls::{BlsPublicKey, BlsSecretKey};
use xc_primitives::Address;

const KEY_FILE: &str = "validator.key";
const BLS_KEY_FILE: &str = "validator.bls.key";

/// Loads a hex-encoded 32-byte seed from `path`, generating and persisting a
/// new random one if absent, and locking the file down to owner-only
/// permissions either way (a key file created before that check existed, or
/// by any other means, still gets restricted on next load).
fn load_or_generate_hex_seed(path: &Path, what: &str) -> Result<[u8; 32]> {
    let seed: [u8; 32] = if path.exists() {
        let hex_seed =
            std::fs::read_to_string(path).with_context(|| format!("failed to read {what} file"))?;
        let seed_bytes =
            hex::decode(hex_seed.trim()).with_context(|| format!("{what} file is not valid hex"))?;
        seed_bytes
            .as_slice()
            .try_into()
            .with_context(|| format!("{what} file must contain a 32-byte seed"))?
    } else {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        std::fs::write(path, hex::encode(seed))
            .with_context(|| format!("failed to persist generated {what}"))?;
        seed
    };

    restrict_key_file_permissions(path)
        .with_context(|| format!("failed to restrict {what} file permissions"))?;

    Ok(seed)
}

/// Loads the validator signing key from `<base_path>/validator.key` (a
/// hex-encoded 32-byte seed), generating and persisting a new one if absent.
/// Logs the resulting address — an operator needs it to know whether this
/// node is in the current genesis validator set and will ever get a turn.
pub fn load_or_generate_key(base_path: &Path) -> Result<SigningKey> {
    let seed = load_or_generate_hex_seed(&base_path.join(KEY_FILE), "validator key")?;
    let key = SigningKey::from_bytes(&seed);

    let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes())
        .context("validator key produced an invalid address")?;
    info!("validator identity: {address}");

    Ok(key)
}

/// Loads the validator's BLS finality-signing key from
/// `<base_path>/validator.bls.key` (a hex-encoded 32-byte seed for
/// `xc_bls::keygen_from_seed`), generating and persisting a new one if
/// absent. Separate file/seed from the Ed25519 `validator.key` — different
/// scheme, and an operator must still submit a `RegisterBlsKey` action for
/// the resulting pubkey before this node's precommit votes count toward
/// finality quorum.
pub fn load_or_generate_bls_key(base_path: &Path) -> Result<(BlsSecretKey, BlsPublicKey)> {
    let seed = load_or_generate_hex_seed(&base_path.join(BLS_KEY_FILE), "BLS key")?;
    xc_bls::keygen_from_seed(&seed).map_err(|_| anyhow::anyhow!("invalid BLS key seed"))
}

#[cfg(unix)]
fn restrict_key_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_key_file_permissions(_path: &Path) -> Result<()> {
    // ponytail: no portable equivalent of chmod 0600 on non-Unix; revisit if
    // this ever needs to run on Windows in production.
    Ok(())
}
