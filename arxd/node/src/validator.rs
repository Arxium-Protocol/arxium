use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::path::Path;
use tracing::info;
use xc_primitives::Address;

const KEY_FILE: &str = "validator.key";

/// Loads the validator signing key from `<base_path>/validator.key` (a
/// hex-encoded 32-byte seed), generating and persisting a new one if absent.
/// Logs the resulting address — an operator needs it to know whether this
/// node is in the current genesis validator set and will ever get a turn.
pub fn load_or_generate_key(base_path: &Path) -> Result<SigningKey> {
    let key_path = base_path.join(KEY_FILE);

    let key = if key_path.exists() {
        let hex_seed =
            std::fs::read_to_string(&key_path).context("failed to read validator key file")?;
        let seed_bytes =
            hex::decode(hex_seed.trim()).context("validator key file is not valid hex")?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .context("validator key file must contain a 32-byte seed")?;
        SigningKey::from_bytes(&seed)
    } else {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        std::fs::write(&key_path, hex::encode(seed))
            .context("failed to persist generated validator key")?;
        SigningKey::from_bytes(&seed)
    };

    // Applied on every load, not just generation, so a key file created
    // before this check existed (or by any other means) still gets locked
    // down — the seed is the validator's full signing key.
    restrict_key_file_permissions(&key_path)
        .context("failed to restrict validator key file permissions")?;

    let address = Address::from_pubkey_bytes(key.verifying_key().as_bytes())
        .context("validator key produced an invalid address")?;
    info!("validator identity: {address}");

    Ok(key)
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
