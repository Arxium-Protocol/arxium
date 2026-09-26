// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::path::Path;
use tracing::info;
use xc_bls::{BlsPublicKey, BlsSecretKey};
use xc_primitives::Address;
use zeroize::Zeroizing;

const KEY_FILE: &str = "validator.key";
const BLS_KEY_FILE: &str = "validator.bls.key";

/// Loads a hex-encoded 32-byte seed from `path`, generating and persisting a
/// new random one if absent, and locking the file down to owner-only
/// permissions either way (a key file created before that check existed, or
/// by any other means, still gets restricted on next load).
///
/// Every buffer that holds the seed (the hex text, its decoded bytes, the
/// returned array) is `Zeroizing`, so no copy of it outlives its use on the
/// heap or stack. `SigningKey` and blst's `SecretKey` already zeroize
/// themselves on drop; this covers the plaintext before it reaches them.
fn load_or_generate_hex_seed(path: &Path, what: &str) -> Result<Zeroizing<[u8; 32]>> {
    let seed: Zeroizing<[u8; 32]> = if path.exists() {
        let hex_seed = Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("failed to read {what} file"))?,
        );
        let seed_bytes = Zeroizing::new(
            hex::decode(hex_seed.trim())
                .with_context(|| format!("{what} file is not valid hex"))?,
        );
        Zeroizing::new(
            seed_bytes
                .as_slice()
                .try_into()
                .with_context(|| format!("{what} file must contain a 32-byte seed"))?,
        )
    } else {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(seed.as_mut());
        let hex_seed = Zeroizing::new(hex::encode(*seed));
        xc_primitives::keyfile::write_new_key_file(path, hex_seed.as_bytes())
            .with_context(|| format!("failed to persist generated {what}"))?;
        seed
    };

    xc_primitives::keyfile::restrict_key_file_permissions(path)
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

const SIGNED_HEIGHT_FILE: &str = "signed_height";

/// Slashing protection: the highest height this validator has signed a
/// block for, in `<base_path>/signed_height` beside the keys, not in the
/// chain DB. A DB restored from a snapshot, rolled back by a crash, or
/// rebuilt on a new machine forgets it proposed `tip+1`; signing a second,
/// different block there is equivocation (`xc_evidence::verify_equivocation`
/// only compares heights), which means a full slash and a tombstone. This
/// file survives all of those, so the node refuses instead.
///
/// Tagged with the genesis hash, so a genesis reset (heights start over)
/// starts from 0 rather than refusing to sign ever again.
pub struct SignedHeight {
    path: std::path::PathBuf,
    genesis: String,
    last: u64,
}

impl SignedHeight {
    pub fn load(base_path: &Path, genesis_hash: &[u8; 32]) -> Result<Self> {
        let path = base_path.join(SIGNED_HEIGHT_FILE);
        let genesis = hex::encode(genesis_hash);
        let last = match std::fs::read_to_string(&path) {
            Ok(text) => match text.split_whitespace().collect::<Vec<_>>()[..] {
                [g, h] if g == genesis => h
                    .parse()
                    .with_context(|| format!("{} holds a malformed height", path.display()))?,
                [_, _] => 0,
                _ => anyhow::bail!(
                    "{} is malformed — expected \"<genesis> <height>\"; restore it rather \
                     than deleting it, or this validator may sign a height twice",
                    path.display()
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e).context("failed to read signed_height"),
        };
        Ok(Self {
            path,
            genesis,
            last,
        })
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    /// Durably claims `height` before the block is signed: temp file,
    /// fsync, rename. A crash after this call only skips our turn at that
    /// height; the reverse order could sign one and forget it.
    pub fn claim(&mut self, height: u64) -> Result<()> {
        anyhow::ensure!(
            height > self.last,
            "refusing to sign height {height}: already signed up to {}",
            self.last
        );
        use std::io::Write;
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp).context("failed to write signed_height")?;
        write!(file, "{} {height}", self.genesis)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path).context("failed to replace signed_height")?;
        self.last = height;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Generation must produce an owner-only file directly. Asserted here as
    /// well as in `xc_primitives::keyfile` because this is the path that
    /// actually mints a validator's signing keys — a regression to
    /// `std::fs::write` + chmod would leave both of them briefly
    /// world-readable, and only this test would notice.
    #[test]
    fn generated_validator_keys_are_never_world_readable() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-validator-keys-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        load_or_generate_key(&dir).unwrap();
        load_or_generate_bls_key(&dir).unwrap();

        for file in [KEY_FILE, BLS_KEY_FILE] {
            let mode = std::fs::metadata(dir.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{file} mode is {mode:o}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod signed_height_tests {
    use super::*;

    /// A restarted validator (fresh `SignedHeight` from the same file) must
    /// refuse any height it already signed; a genesis reset must not.
    #[test]
    fn signed_height_survives_restart_and_resets_with_genesis() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-signed-height-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut signed = SignedHeight::load(&dir, &[1; 32]).unwrap();
        assert_eq!(signed.last(), 0);
        signed.claim(5).unwrap();

        let mut restarted = SignedHeight::load(&dir, &[1; 32]).unwrap();
        assert_eq!(restarted.last(), 5);
        assert!(restarted.claim(5).is_err(), "same height twice");
        assert!(restarted.claim(4).is_err(), "going back");
        restarted.claim(6).unwrap();

        let reset = SignedHeight::load(&dir, &[2; 32]).unwrap();
        assert_eq!(reset.last(), 0, "a new genesis starts over");

        std::fs::write(dir.join(SIGNED_HEIGHT_FILE), "garbage").unwrap();
        assert!(
            SignedHeight::load(&dir, &[1; 32]).is_err(),
            "corrupt file is fatal"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
