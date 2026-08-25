// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use libp2p::identity::Keypair;
use std::path::Path;

const KEY_FILE: &str = "network.key";

/// DEVNET ONLY — well-known network identity seed, matching the pattern of
/// `arxd/node/specs/devnet-keys.json`'s validator seeds. A node started with
/// `--bootnode` writes this seed to its `network.key` instead of generating
/// one at random, so its PeerId (and therefore its multiaddr) is fixed and
/// can be hardcoded as everyone else's default `--bootnodes` value. Never
/// use on anything but a local devnet — anyone can derive this node's
/// private key from the constant below.
pub const DEVNET_BOOTNODE_SEED: [u8; 32] = [0xB0; 32];

/// Loads this node's libp2p identity keypair from `<base_path>/network.key`
/// (protobuf-encoded, libp2p's own format), generating and persisting a new
/// one if absent. This is the "who are you on the wire" identity — separate
/// from the validator signing key (`arxd/node/src/validator.rs`), which
/// answers "are you allowed to sign blocks". Every node has one of these,
/// validator or not.
pub fn load_or_generate_keypair(base_path: &Path) -> Result<Keypair> {
    load_or_generate_keypair_inner(base_path, None)
}

/// Same as `load_or_generate_keypair`, but on first boot (no `network.key`
/// yet) writes `DEVNET_BOOTNODE_SEED` instead of a random identity — for the
/// one node other nodes' default `--bootnodes` value expects to find at a
/// fixed PeerId.
pub fn load_or_generate_devnet_bootnode_keypair(base_path: &Path) -> Result<Keypair> {
    load_or_generate_keypair_inner(base_path, Some(DEVNET_BOOTNODE_SEED))
}

fn load_or_generate_keypair_inner(base_path: &Path, fixed_seed: Option<[u8; 32]>) -> Result<Keypair> {
    let key_path = base_path.join(KEY_FILE);

    let keypair = if key_path.exists() {
        let bytes = std::fs::read(&key_path).context("failed to read network key file")?;
        Keypair::from_protobuf_encoding(&bytes)
            .context("network key file is not valid protobuf-encoded keypair")?
    } else {
        let keypair = match fixed_seed {
            Some(mut seed) => {
                Keypair::ed25519_from_bytes(&mut seed).context("invalid devnet bootnode seed")?
            }
            None => Keypair::generate_ed25519(),
        };
        let bytes = keypair
            .to_protobuf_encoding()
            .context("failed to encode generated network key")?;
        std::fs::write(&key_path, bytes).context("failed to persist generated network key")?;
        keypair
    };

    // Applied on every load, not just generation, mirroring validator.rs —
    // a key file created before this check existed still gets locked down.
    restrict_key_file_permissions(&key_path)
        .context("failed to restrict network key file permissions")?;

    Ok(keypair)
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
