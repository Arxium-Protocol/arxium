// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use bech32::{Bech32, Hrp};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(String);

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("Address missing prefix 'arx1'")]
    MissingPrefix,
    #[error("Address must be 32 bytes after prefix, got {0}")]
    WrongLength(usize),
    #[error("Address contains non-hex characters")]
    InvalidHex,
}

const HRP: Hrp = Hrp::parse_unchecked("arx");

impl Address {
    pub fn from_pubkey_bytes(bytes: &[u8]) -> Result<Self, AddressError> {
        let encoded = bech32::encode::<Bech32>(HRP, bytes).map_err(|_| AddressError::InvalidHex)?;
        Ok(Self(encoded))
    }

    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let (hrp, _data) = bech32::decode(s).map_err(|_| AddressError::InvalidHex)?;
        if hrp != HRP {
            return Err(AddressError::MissingPrefix);
        }
        Ok(Self(s.to_string()))
    }

    /// Decodes the raw pubkey bytes this address was derived from.
    pub fn pubkey_bytes(&self) -> Result<Vec<u8>, AddressError> {
        let (hrp, data) = bech32::decode(&self.0).map_err(|_| AddressError::InvalidHex)?;
        if hrp != HRP {
            return Err(AddressError::MissingPrefix);
        }
        Ok(data)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
