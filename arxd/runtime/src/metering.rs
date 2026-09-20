// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Proof-of-Execution resource metering for CoreChain: the weight of an
//! action, and the fee that weight costs.
//!
//! Substrate's model, sized to action granularity: a weight is nominal
//! microseconds of execution on the devnet reference host, a block carries at
//! most `ChainParams.max_block_weight` of it, and the fee is
//! `ACTION_FEE + weight × WEIGHT_FEE`. The one rule that matters is the
//! Substrate one — a weight that *underestimates* cost is a DoS vector — so
//! every entry errs high and the two fault-submission variants, which replay
//! a whole block's worth of dispatch and verify BLS signatures, weigh what a
//! block costs.
//!
//! ponytail: the table is hand-set from what each variant does (signature
//! checks, ZK verify, trie reads/writes). The upgrade path is a benchmark
//! harness that regenerates it from measured medians, Substrate-style; until
//! one exists these are the consensus values and changing one is a
//! `reset-required` bump like any other root-affecting constant.

use crate::{ActionPayload, ChainAction};

/// IUM charged per weight unit on top of `ACTION_FEE`. At the table below a
/// `Transfer` costs `ACTION_FEE + 50 × WEIGHT_FEE` = 0.0015 ARX.
pub const WEIGHT_FEE: u128 = 10_000;

/// Weight per encoded byte, so an action's size is paid for regardless of
/// variant — an `artifact_json` or `metadata_uri` cannot be free just because
/// its variant is cheap.
const WEIGHT_PER_BYTE: u64 = 1;

/// Fixed cost per variant, excluding the per-byte term. Every action already
/// pays for one ed25519 verify and a nonce/balance read-modify-write, which
/// is the 50 floor.
fn base_weight(payload: &ActionPayload) -> u64 {
    use ActionPayload::*;
    match payload {
        Transfer { .. } => 50,
        // Stake bookkeeping touches the allocation, the validator index and
        // the master account.
        Stake { .. } | Unstake { .. } => 100,
        // Join/register add a BLS proof-of-possession verify (~1ms).
        JoinValidator { .. } | RegisterBlsKey { .. } => 1_500,
        LeaveValidator { .. } => 150,
        AuthorizeOperator { .. } | RevokeOperator => 100,
        // Groth16 verify over BLS12-381.
        VerifyIdentityCredential { .. } => 5_000,
        GrantAttestation { .. } | RevokeAttestation { .. } => 100,
        RegisterAttestor { .. } | DeregisterAttestor { .. } => 100,
        RegisterAsset { .. } => 150,
        IssueAsset { .. }
        | IssueAssetTo { .. }
        | TransferAsset { .. }
        | ForcedTransfer { .. }
        | IssuerForcedTransfer { .. }
        | BurnAsset { .. }
        | RecoverHolder { .. } => 150,
        FreezeAsset { .. }
        | UnfreezeAsset { .. }
        | SetHolderFrozen { .. }
        | LockHolderAmount { .. }
        | LockHolderAmountUntil { .. }
        | UnlockHolderAmount { .. }
        | SetAssetLimits { .. }
        | LockIssuance { .. }
        | TransferIssuer { .. }
        | SetAssetMetadataUri { .. } => 100,
        // A validator-set read plus one or two governance rows.
        SubmitProposal { .. } | VoteProposal { .. } | ExecuteProposal { .. } => 150,
        // Two block-signature verifies plus the slash.
        SubmitEquivocationEvidence { .. } => 2_000,
        // Verifies the artifact's BLS signatures and replays up to
        // `MAX_ADJUDICATED_ACTIONS` of dispatch: budgeted as a block.
        SubmitExecutionFault { .. } => 500_000,
    }
}

/// `ChainRuntime::action_weight` for CoreChain.
pub fn action_weight(action: &ChainAction) -> u64 {
    let bytes = bincode::serde::encode_to_vec(action, bincode::config::standard())
        .map(|b| b.len() as u64)
        .unwrap_or(u64::MAX / WEIGHT_PER_BYTE.max(1));
    base_weight(&action.payload).saturating_add(bytes.saturating_mul(WEIGHT_PER_BYTE))
}

/// `ChainRuntime::action_fee_for` for CoreChain.
pub fn action_fee_for(weight: u64) -> u128 {
    crate::ACTION_FEE.saturating_add(u128::from(weight).saturating_mul(WEIGHT_FEE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xc_primitives::{Action, Address};

    #[test]
    fn weight_grows_with_payload_size_and_fee_grows_with_weight() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let small = Action {
            sender: alice.clone(),
            nonce: 0,
            signature: None,
            payload: ActionPayload::SetAssetMetadataUri {
                asset: xc_primitives::AssetRef::derive(&alice, "x").unwrap(),
                metadata_uri: Some("a".into()),
            },
        };
        let large = Action {
            payload: ActionPayload::SetAssetMetadataUri {
                asset: xc_primitives::AssetRef::derive(&alice, "x").unwrap(),
                metadata_uri: Some("a".repeat(1_000)),
            },
            ..small.clone()
        };
        assert!(action_weight(&large) > action_weight(&small) + 900);
        assert!(action_fee_for(action_weight(&large)) > action_fee_for(action_weight(&small)));
        assert_eq!(action_fee_for(0), crate::ACTION_FEE);
        // Every variant fits in a default block on its own.
        assert!(action_weight(&large) < xc_primitives::ChainParams::default().max_block_weight);
    }
}
