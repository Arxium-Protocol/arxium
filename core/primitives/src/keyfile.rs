// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Creating and locking down on-disk secret key files. Shared so the node's
//! validator/BLS keys and the network identity key can't drift apart on the
//! one thing that matters here: the file is never readable by anyone but its
//! owner, including for the instant right after it is created.

use std::io;
use std::path::Path;

/// Creates `path` owner-only and writes `contents` to it.
///
/// The mode is set *at creation* rather than chmod'd afterwards: writing with
/// `std::fs::write` creates the file 0666 & ~umask (typically 0644), so a
/// freshly generated signing key — one whose compromise means equivocation
/// and a full-stake slash — sits on disk world-readable until the chmod lands.
/// `create_new` also means this can never silently overwrite an existing key.
pub fn write_new_key_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = create_owner_only(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> io::Result<std::fs::File> {
    // ponytail: no portable equivalent of creating at 0600 on non-Unix;
    // revisit if this ever needs to run on Windows in production.
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

/// Locks an *already existing* key file down to owner-only. Applied on every
/// load, not just on generation, so a key file created before this check
/// existed — or copied in by other means — still gets restricted.
#[cfg(unix)]
pub fn restrict_key_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn restrict_key_file_permissions(_path: &Path) -> io::Result<()> {
    // ponytail: as above — no portable equivalent of chmod 0600.
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The mode has to be right the moment the file exists, not after a
    /// follow-up chmod — that window is the whole finding.
    #[test]
    fn a_new_key_file_is_owner_only_from_the_moment_it_exists() {
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-keyfile-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("validator.key");

        write_new_key_file(&path, b"deadbeef").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode is {mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), b"deadbeef");

        // Never clobber an existing key.
        assert_eq!(
            write_new_key_file(&path, b"other").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"deadbeef");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
