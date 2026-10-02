// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use crate::{Address, AssetRef, SignatureError, multisig_address};
use serde::{Deserialize, Serialize};

pub const MAX_POLICY_RECIPIENTS: usize = 64;
pub const MAX_POLICY_LIMITS: usize = 16;
pub const MAX_SESSION_KEYS: usize = 16;

pub(crate) fn validate_account_address(address: &Address) -> Result<(), SignatureError> {
    if !matches!(address.to_string().len(), 62 | 63) {
        return Err(SignatureError::BadMultisig(
            "account address has invalid length",
        ));
    }
    let bytes = address.pubkey_bytes()?;
    if !(bytes.len() == 32 || (bytes.len() == 33 && bytes[0] == 1))
        || Address::from_pubkey_bytes(&bytes)? != *address
    {
        return Err(SignatureError::BadMultisig(
            "account address must be canonical",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdPolicy {
    pub threshold: u8,
    /// Strictly ascending, unique Ed25519 public keys.
    pub members: Vec<[u8; 32]>,
}

impl ThresholdPolicy {
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.members.windows(2).any(|w| w[0] >= w[1]) {
            return Err(SignatureError::BadMultisig(
                "members must be unique and ascending",
            ));
        }
        multisig_address(self.threshold, &self.members)?;
        for member in &self.members {
            let key = ed25519_dalek::VerifyingKey::from_bytes(member)
                .map_err(|_| SignatureError::Invalid)?;
            if key.is_weak() {
                return Err(SignatureError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpendAsset {
    Native,
    Asset(AssetRef),
}

impl SpendAsset {
    fn validate(&self) -> Result<(), SignatureError> {
        if let Self::Asset(asset) = self {
            let text = asset.to_string();
            if text.len() != 67 {
                return Err(SignatureError::BadMultisig("asset ref has invalid length"));
            }
            let parsed = AssetRef::parse(&text)
                .map_err(|_| SignatureError::BadMultisig("invalid spending asset ref"))?;
            if AssetRef::from_bytes(&parsed.bytes()) != *asset {
                return Err(SignatureError::BadMultisig("asset ref must be canonical"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingLimit {
    pub asset: SpendAsset,
    pub period_blocks: u64,
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendCounter {
    pub asset: SpendAsset,
    pub window: u64,
    pub spent: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub public_key: [u8; 32],
    /// Exclusive expiry; valid only at heights strictly below this value.
    pub expires_at: u64,
    pub asset: SpendAsset,
    pub allowance: u128,
    pub recipients: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub guardians: ThresholdPolicy,
    pub delay_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecovery {
    pub owners: ThresholdPolicy,
    pub execute_after: u64,
}

/// Fixed policy menu. The address remains unchanged when owners rotate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPolicy {
    pub owners: ThresholdPolicy,
    pub limits: Vec<SpendingLimit>,
    /// None is unrestricted; Some([]) permits no recipients.
    pub recipients: Option<Vec<Address>>,
    pub sessions: Vec<SessionKey>,
    pub recovery: Option<RecoveryPolicy>,
}

impl AccountPolicy {
    pub fn validate(&self) -> Result<(), SignatureError> {
        self.owners.validate()?;
        if self.limits.len() > MAX_POLICY_LIMITS || self.sessions.len() > MAX_SESSION_KEYS {
            return Err(SignatureError::BadMultisig("policy exceeds bounded menu"));
        }
        for (i, limit) in self.limits.iter().enumerate() {
            limit.asset.validate()?;
            if limit.period_blocks == 0 || self.limits[..i].iter().any(|l| l.asset == limit.asset) {
                return Err(SignatureError::BadMultisig(
                    "invalid or duplicate spending limit",
                ));
            }
        }
        fn recipients(v: &[Address]) -> Result<(), SignatureError> {
            if v.len() > MAX_POLICY_RECIPIENTS || v.windows(2).any(|w| w[0] >= w[1]) {
                return Err(SignatureError::BadMultisig(
                    "recipients must be bounded, unique and ascending",
                ));
            }
            for address in v {
                validate_account_address(address)?;
            }
            Ok(())
        }
        if let Some(v) = &self.recipients {
            recipients(v)?;
        }
        for (i, session) in self.sessions.iter().enumerate() {
            session.asset.validate()?;
            recipients(&session.recipients)?;
            ThresholdPolicy {
                threshold: 1,
                members: vec![session.public_key],
            }
            .validate()?;
            if self.sessions[..i]
                .iter()
                .any(|s| s.public_key == session.public_key)
            {
                return Err(SignatureError::BadMultisig("duplicate session key"));
            }
        }
        if !self.sessions.is_empty() && !self.limits.iter().any(|l| l.asset == SpendAsset::Native) {
            return Err(SignatureError::BadMultisig(
                "session keys require a native spending limit to bound fees",
            ));
        }
        if let Some(recovery) = &self.recovery {
            recovery.guardians.validate()?;
            if recovery.delay_blocks == 0 {
                return Err(SignatureError::BadMultisig(
                    "recovery delay must be positive",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgrammableAccount {
    pub policy: AccountPolicy,
    pub counters: Vec<SpendCounter>,
    pub pending_recovery: Option<PendingRecovery>,
}

/// Appended payload family, with an append-only variant order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccountPolicyAction {
    SetPolicy { policy: AccountPolicy },
    RotateMembers { owners: ThresholdPolicy },
    AddSession { session: SessionKey },
    RevokeSession { public_key: [u8; 32] },
    StartRecovery { owners: ThresholdPolicy },
    CancelRecovery,
    ExecuteRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyAuthorization {
    Owner,
    Session(usize),
    Guardian,
}

/// Prefix for stateful witnesses; mode 0 owner, 1 session, 2 guardian.
/// Threshold modes wrap the existing canonical multisig witness. Session mode
/// wraps public key (32 bytes) and signature (64 bytes).
pub fn policy_signature(mode: u8, witness: &str) -> Result<String, SignatureError> {
    if mode > 2 {
        return Err(SignatureError::Invalid);
    }
    let bytes = hex::decode(witness).map_err(|_| SignatureError::InvalidHex)?;
    Ok(format!("a7{mode:02x}{}", hex::encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_weak_keys_and_unbounded_or_malformed_identifiers() {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let mut policy = AccountPolicy {
            owners: ThresholdPolicy {
                threshold: 1,
                members: vec![public_key],
            },
            limits: vec![],
            recipients: None,
            sessions: vec![],
            recovery: None,
        };
        policy.validate().unwrap();
        policy.owners.members = vec![[0; 32]];
        assert!(policy.validate().is_err());
        policy.owners.members = vec![public_key];
        policy.recipients = Some(vec![Address::from_pubkey_bytes(&[7; 34]).unwrap()]);
        assert!(policy.validate().is_err());
        policy.recipients = None;
        let malformed: AssetRef = serde_json::from_str("\"not-an-asset-ref\"").unwrap();
        policy.limits.push(SpendingLimit {
            asset: SpendAsset::Asset(malformed),
            period_blocks: 10,
            amount: 100,
        });
        assert!(policy.validate().is_err());
        policy.limits.clear();
        policy.sessions.push(SessionKey {
            public_key,
            expires_at: 10,
            asset: SpendAsset::Native,
            allowance: 10,
            recipients: vec![],
        });
        assert!(
            policy.validate().is_err(),
            "session must have a native fee budget"
        );
    }
}
