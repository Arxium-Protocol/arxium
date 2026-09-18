// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// A 32-byte hash carried on the wire as a hex string, but compared and
/// hashed on its bytes instead of the string — so `0xABCD...` and `abcd...`
/// (same hash, different case/prefix) are never mistakenly treated as
/// different values. Before this type, every call site that received such a
/// string had to remember to normalize it itself; most didn't, which is why
/// `arxd_runtime::consensus::genesis_hash_matches` had to exist at all.
///
/// `Display`/`Serialize` always emit `0x` + lowercase hex; `FromStr`/
/// `Deserialize` accept either case and an optional `0x`/`0X` prefix, so a
/// value round-trips regardless of which convention produced it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Hash32Error {
    #[error("hash must be 32 bytes, got {0}")]
    WrongLength(usize),
    #[error("hash contains non-hex characters")]
    InvalidHex,
}

impl Hash32 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse(s: &str) -> Result<Self, Hash32Error> {
        let hex_part = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let bytes = hex::decode(hex_part).map_err(|_| Hash32Error::InvalidHex)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| Hash32Error::WrongLength(v.len()))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({self})")
    }
}

impl FromStr for Hash32 {
    type Err = Hash32Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// Ergonomics for literal comparisons in tests (`assert_eq!(record.block_hash, "0xaaa")`)
// without every caller having to parse both sides first. Only ever compares
// on the decoded bytes, same as `PartialEq` between two `Hash32`s.
impl PartialEq<str> for Hash32 {
    fn eq(&self, other: &str) -> bool {
        Hash32::parse(other).is_ok_and(|h| h == *self)
    }
}

impl PartialEq<&str> for Hash32 {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED_UPPER: &str = "0xAABBCC0000000000000000000000000000000000000000000000000000000000";
    const BARE_LOWER: &str = "aabbcc0000000000000000000000000000000000000000000000000000000000";
    const CAPITAL_X_PREFIX: &str =
        "0Xaabbcc0000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn parse_accepts_both_case_and_prefix_conventions() {
        let a = Hash32::parse(MIXED_UPPER).unwrap();
        let b = Hash32::parse(BARE_LOWER).unwrap();
        let c = Hash32::parse(CAPITAL_X_PREFIX).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn display_is_always_canonical_lowercase_with_prefix() {
        let h = Hash32::parse(MIXED_UPPER).unwrap();
        assert_eq!(h.to_string(), format!("0x{BARE_LOWER}"));
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert_eq!(Hash32::parse("0xab"), Err(Hash32Error::WrongLength(1)));
    }

    #[test]
    fn round_trips_through_json_regardless_of_input_case() {
        let json = format!("\"{MIXED_UPPER}\"");
        let h: Hash32 = serde_json::from_str(&json).unwrap();
        assert_eq!(
            serde_json::to_string(&h).unwrap(),
            format!("\"0x{}\"", BARE_LOWER)
        );
    }

    #[test]
    fn literal_str_comparison_ignores_case_and_prefix() {
        let h = Hash32::parse(MIXED_UPPER).unwrap();
        assert_eq!(h, BARE_LOWER);
        assert_eq!(h, MIXED_UPPER);
    }
}
