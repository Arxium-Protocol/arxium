// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Rules every attestor registration obeys, voted in or seeded at genesis:
//! a name that cannot impersonate another attestor, and an address that is
//! provably a multisig.

use crate::{Address, multisig_address};

pub const MIN_ATTESTOR_NAME_LEN: usize = 3;
pub const MAX_ATTESTOR_NAME_LEN: usize = 64;
/// Fewer than two signers is a single key, which is what mandatory multisig
/// exists to avoid.
pub const MIN_ATTESTOR_THRESHOLD: u8 = 2;

/// ASCII letters and digits, with single spaces and `.-&'()` between them.
/// ASCII only: a Unicode name could pair a Cyrillic "а" with a Latin "a".
pub fn validate_attestor_name(name: &str) -> Result<(), &'static str> {
    if !(MIN_ATTESTOR_NAME_LEN..=MAX_ATTESTOR_NAME_LEN).contains(&name.len()) {
        return Err("attestor name must be 3 to 64 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" .-&'()".contains(&b))
    {
        return Err("attestor name allows only ASCII letters, digits, space and . - & ' ( )");
    }
    if name.starts_with(' ') || name.ends_with(' ') || name.contains("  ") {
        return Err("attestor name has stray spaces");
    }
    if !name.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return Err("attestor name needs a letter or digit");
    }
    Ok(())
}

/// What two names must differ in to be distinct attestors: case, spacing and
/// punctuation are dropped, and the ASCII lookalikes `0 1 5 i` fold onto
/// `o l s l`, so "Arxium Bank" and "ARX1UM bank" collide.
pub fn attestor_name_skeleton(name: &str) -> String {
    name.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|b| match b.to_ascii_lowercase() {
            b'0' => 'o',
            b'1' | b'i' => 'l',
            b'5' => 's',
            other => other as char,
        })
        .collect()
}

/// `attestor` must be the `threshold`-of-`owners` multisig address with a
/// threshold of at least two. An address is only a hash, so this is the one
/// place the chain can check who is behind it.
pub fn validate_attestor_multisig(
    attestor: &Address,
    owners: &[Address],
    threshold: u8,
) -> Result<(), &'static str> {
    if threshold < MIN_ATTESTOR_THRESHOLD {
        return Err("attestor multisig threshold must be at least 2");
    }
    let members = owners
        .iter()
        .map(|o| o.pubkey_bytes().ok()?.try_into().ok())
        .collect::<Option<Vec<[u8; 32]>>>()
        .ok_or("attestor owners must be single-key addresses")?;
    let derived = multisig_address(threshold, &members)
        .map_err(|_| "attestor owners must be 2 to 16 unique keys, at least `threshold` of them")?;
    if &derived != attestor {
        return Err("attestor address is not the multisig of its owners and threshold");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Address {
        Address::from_pubkey_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn names_are_ascii_and_lookalikes_collide() {
        validate_attestor_name("Arxium (genesis attestor)").unwrap();
        for bad in [
            "ab",
            " Arxium",
            "Arx  ium",
            "Arxium!",
            "Arxіum",
            "---",
            "Arx\u{200b}ium",
        ] {
            assert!(validate_attestor_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            attestor_name_skeleton("Arxium Bank"),
            attestor_name_skeleton("ARX1UM  b-ank")
        );
        assert_ne!(
            attestor_name_skeleton("Arxium Bank"),
            attestor_name_skeleton("Arxium Banks")
        );
    }

    #[test]
    fn the_address_must_be_the_multisig_of_its_owners() {
        let owners = [key(1), key(2), key(3)];
        let members: Vec<[u8; 32]> = (1..=3).map(|b| [b; 32]).collect();
        let address = multisig_address(2, &members).unwrap();
        validate_attestor_multisig(&address, &owners, 2).unwrap();
        // Owner order does not matter; a different threshold or set does.
        validate_attestor_multisig(&address, &[key(3), key(1), key(2)], 2).unwrap();
        assert!(validate_attestor_multisig(&address, &owners, 3).is_err());
        assert!(validate_attestor_multisig(&address, &[key(1), key(2), key(4)], 2).is_err());
        assert!(validate_attestor_multisig(&key(1), &owners, 2).is_err());
        // One-of-n is a single key in practice.
        let one = multisig_address(1, &members).unwrap();
        assert!(validate_attestor_multisig(&one, &owners, 1).is_err());
        // A repeated owner would let one key meet the threshold twice.
        assert!(validate_attestor_multisig(&address, &[key(1), key(1), key(2)], 2).is_err());
    }
}
