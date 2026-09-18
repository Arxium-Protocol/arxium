// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `AssetRef` — the chain-wide identity of a regulated asset.
//!
//! Derived, never chosen: `H("arxium/asset/v1" || issuer_pubkey || 0x00 ||
//! asset_id)`, so provenance is welded to the identifier and two issuers
//! can both register `gold` without either being able to squat on the
//! other's. `asset_id` is only a slug unique within one issuer; everything
//! that resolves an asset — storage keys, action payloads, RPC — goes by the
//! ref. `symbol` and `name` on the record are display-only and never
//! resolve anything.

use crate::{Address, AddressError};
use bech32::{Bech32, Hrp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Rendered bech32 with HRP `arxasset`, held as the encoded string exactly
/// like `Address` so the client codecs reuse their one bech32 string writer
/// instead of growing a second `[u8; 32]` path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AssetRef(String);

const HRP: Hrp = Hrp::parse_unchecked("arxasset");
const DOMAIN: &[u8] = b"arxium/asset/v1";

#[derive(Debug, thiserror::Error)]
pub enum AssetRefError {
    #[error("asset ref missing prefix 'arxasset1'")]
    MissingPrefix,
    #[error("asset ref is not valid bech32")]
    InvalidEncoding,
    #[error("asset ref must carry 32 bytes, got {0}")]
    WrongLength(usize),
}

impl AssetRef {
    /// SHA-256 — the same primitive the rest of the tree uses for block
    /// hashes and state, so this introduces no second hash. The `0x00`
    /// separator sits between the two variable-length parts so
    /// `(issuer, "ab")` can never be confused with a differently-split
    /// concatenation of the same bytes.
    pub fn derive(issuer: &Address, asset_id: &str) -> Result<Self, AddressError> {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(issuer.pubkey_bytes()?);
        hasher.update([0u8]);
        hasher.update(asset_id.as_bytes());
        Ok(Self::from_bytes(&hasher.finalize().into()))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(bech32::encode::<Bech32>(HRP, bytes).expect("32 bytes always encode"))
    }

    pub fn parse(s: &str) -> Result<Self, AssetRefError> {
        let (hrp, data) = bech32::decode(s).map_err(|_| AssetRefError::InvalidEncoding)?;
        if hrp != HRP {
            return Err(AssetRefError::MissingPrefix);
        }
        if data.len() != 32 {
            return Err(AssetRefError::WrongLength(data.len()));
        }
        Ok(Self(s.to_string()))
    }

    /// The 32 hash bytes behind the bech32 rendering.
    pub fn bytes(&self) -> [u8; 32] {
        let (_, data) = bech32::decode(&self.0).expect("constructed from valid bech32");
        data.try_into().expect("checked at construction")
    }
}

impl fmt::Display for AssetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AssetRef {
    type Err = AssetRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "arx132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqaq6lsz";
    const BOB: &str = "arx1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qpghjk5";

    /// Pinned forever: `(ALICE, "gold")`. Greppable from Retracer and the
    /// Console so their derivations can be checked against the node's.
    pub const ALICE_GOLD_REF: &str =
        "arxasset1z8d4jt8yt0xtjm6lvk8umc9relegrwq4xu928eqxyjfcsnjuex6qe873qa";

    #[test]
    fn a_fixed_pair_derives_the_pinned_constant() {
        let alice = Address::parse(ALICE).unwrap();
        assert_eq!(
            AssetRef::derive(&alice, "gold").unwrap().to_string(),
            ALICE_GOLD_REF
        );
    }

    #[test]
    fn round_trips_through_string_and_serde() {
        let r = AssetRef::derive(&Address::parse(ALICE).unwrap(), "gold").unwrap();
        assert_eq!(AssetRef::parse(&r.to_string()).unwrap(), r);
        assert_eq!(r.to_string().parse::<AssetRef>().unwrap(), r);
        assert_eq!(AssetRef::from_bytes(&r.bytes()), r);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            format!("\"{r}\""),
            "serializes as a plain string, like Address"
        );
        assert_eq!(serde_json::from_str::<AssetRef>(&json).unwrap(), r);
    }

    #[test]
    fn same_slug_under_two_issuers_is_two_refs() {
        let alice = Address::parse(ALICE).unwrap();
        let bob = Address::parse(BOB).unwrap();
        assert_ne!(
            AssetRef::derive(&alice, "gold").unwrap(),
            AssetRef::derive(&bob, "gold").unwrap()
        );
    }

    /// Without the separator, `H(domain || pubkey || id)` would let a pubkey
    /// whose last byte equals an id's first byte collide with a shifted
    /// split. Real pubkeys are fixed-width so the risk is theoretical, but
    /// the separator is part of the pinned derivation, so it is exercised.
    #[test]
    fn the_separator_is_part_of_the_preimage() {
        let alice = Address::parse(ALICE).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(alice.pubkey_bytes().unwrap());
        hasher.update(b"gold");
        let without = AssetRef::from_bytes(&hasher.finalize().into());
        assert_ne!(AssetRef::derive(&alice, "gold").unwrap(), without);
    }

    #[test]
    fn rejects_wrong_hrp_and_length() {
        assert!(matches!(
            AssetRef::parse(ALICE),
            Err(AssetRefError::MissingPrefix)
        ));
        let short = bech32::encode::<Bech32>(HRP, &[1u8; 20]).unwrap();
        assert!(matches!(
            AssetRef::parse(&short),
            Err(AssetRefError::WrongLength(20))
        ));
        assert!(matches!(
            AssetRef::parse("nonsense"),
            Err(AssetRefError::InvalidEncoding)
        ));
    }
}
