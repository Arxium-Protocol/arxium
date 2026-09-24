// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Shared, network-free verification used by the CLI and browser.

use serde::{Deserialize, Serialize};
use xc_artifact::{EvidenceArtifact, Verdict};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "UPPERCASE")]
pub enum EvidenceResult {
    Valid {
        fault: String,
        genesis_hash: String,
        culpable_pubkey: String,
    },
    Unresolved {
        fault: String,
        genesis_hash: String,
        parties: Vec<String>,
        note: String,
    },
    Invalid {
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        genesis_hash: Option<String>,
    },
}

pub fn verify_evidence(json: &str) -> EvidenceResult {
    let artifact: EvidenceArtifact = match serde_json::from_str(json) {
        Ok(artifact) => artifact,
        Err(err) => {
            return EvidenceResult::Invalid {
                error: format!("not a valid evidence artifact: {err}"),
                genesis_hash: None,
            };
        }
    };
    let genesis_hash = artifact.genesis_hash.clone();
    match xc_artifact::verify(&artifact) {
        Ok(Verdict::Culpable {
            fault,
            culpable_pubkey,
        }) => EvidenceResult::Valid {
            fault: fault.into(),
            genesis_hash,
            culpable_pubkey,
        },
        Ok(Verdict::Disagreement { fault, parties }) => {
            #[cfg(feature = "core-adjudicate")]
            {
                use arxd_runtime::adjudicate::{self, AdjudicationOutcome};
                use xc_artifact::Fault;
                let outcome = if matches!(artifact.fault, Fault::ActionDivergence { .. }) {
                    Some(adjudicate::adjudicate_action_divergence(&artifact))
                } else if matches!(artifact.fault, Fault::BlockDivergence { .. }) {
                    Some(adjudicate::adjudicate_block_divergence(&artifact))
                } else {
                    None
                };
                if let Some(outcome) = outcome {
                    return match outcome {
                        Ok(AdjudicationOutcome::Culpable { culpable_pubkey }) => {
                            EvidenceResult::Valid {
                                fault: fault.into(),
                                genesis_hash,
                                culpable_pubkey,
                            }
                        }
                        Ok(AdjudicationOutcome::Disagreement { reason }) => {
                            EvidenceResult::Unresolved {
                                fault: fault.into(),
                                genesis_hash,
                                parties,
                                note: reason,
                            }
                        }
                        Err(err) => EvidenceResult::Invalid {
                            error: err.to_string(),
                            genesis_hash: Some(genesis_hash),
                        },
                    };
                }
            }
            EvidenceResult::Unresolved {
                fault: fault.into(), genesis_hash, parties,
                note: "this artifact proves a proposer/validator execution disagreement, not who is at fault".into(),
            }
        }
        Err(err) => EvidenceResult::Invalid {
            error: err.to_string(),
            genesis_hash: Some(genesis_hash),
        },
    }
}

/// A subset of GET /accounts/{address}/proof (also used by other state endpoints).
#[derive(Deserialize, Serialize)]
struct StateProofResponse {
    key: String,
    value: serde_json::Value,
    proof: xc_artifact::StateProof,
    height: u64,
    state_root: String,
    block_hash: String,
    parent_state_root: String,
    weight_used: u64,
    block: BlockHeader,
    finality: Option<Finality>,
}

#[derive(Deserialize, Serialize)]
struct BlockHeader {
    tx_root: [u8; 32],
    state_root: String,
}

#[derive(Deserialize, Serialize)]
struct Finality {
    height: u64,
    block_hash: String,
    ep: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "UPPERCASE")]
pub enum StateProofResult {
    Valid {
        key: String,
        value: serde_json::Value,
        height: u64,
        block_hash: String,
        certified: String,
    },
    Invalid {
        error: String,
    },
}

fn decode_root(root: &str) -> Result<[u8; 32], String> {
    hex::decode(root.strip_prefix("0x").unwrap_or(root))
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| format!("{root} is not a 32-byte root"))
}

fn check_state_proof(response: &StateProofResponse) -> Result<(), String> {
    let root = decode_root(&response.state_root)?;
    xc_artifact::verify_state_proof(root, &response.proof)
        .map_err(|e| format!("merkle path: {e}"))?;
    if response.block.state_root != response.state_root {
        return Err("state_root is not the named block's".into());
    }
    match &response.finality {
        Some(finality) => {
            if finality.height != response.height || finality.block_hash != response.block_hash {
                return Err("finality certificate names a different block".into());
            }
            let ep = xc_poe::block_ep(
                &response.parent_state_root,
                &response.block.tx_root,
                &response.state_root,
                response.weight_used,
            );
            if ep != finality.ep {
                return Err("state_root is not bound to the certificate's execution proof".into());
            }
        }
        None if response.height == 0 => {}
        None => return Err("no finality certificate for a non-genesis height".into()),
    }
    Ok(())
}

pub fn verify_state_proof(json: &str) -> StateProofResult {
    let response: StateProofResponse = match serde_json::from_str(json) {
        Ok(response) => response,
        Err(err) => {
            return StateProofResult::Invalid {
                error: format!("not a state-proof response: {err}"),
            };
        }
    };
    match check_state_proof(&response) {
        Ok(()) => StateProofResult::Valid {
            key: response.key,
            value: response.value,
            height: response.height,
            block_hash: response.block_hash,
            certified: if response.finality.is_some() {
                "yes"
            } else {
                "genesis root, no certificate"
            }
            .into(),
        },
        Err(error) => StateProofResult::Invalid { error },
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn verify_evidence(json: &str) -> String {
        serde_json::to_string(&super::verify_evidence(json)).expect("verdict serializes")
    }

    #[wasm_bindgen]
    pub fn verify_state_proof(json: &str) -> String {
        serde_json::to_string(&super::verify_state_proof(json)).expect("result serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_binds_the_root_through_the_ep() {
        let empty_root = xc_poe::state_trie::default_hashes()[256];
        let state_root = format!("0x{}", hex::encode(empty_root));
        let ep = xc_poe::block_ep("0xparent", &[9u8; 32], &state_root, 123);
        let response = |ep| StateProofResponse {
            key: "account:nobody".into(),
            value: serde_json::Value::Null,
            proof: xc_artifact::StateProof {
                key_hash: format!(
                    "0x{}",
                    hex::encode(xc_poe::state_trie::hash_key(b"account:nobody"))
                ),
                value: None,
                siblings_bitmap: format!("0x{}", hex::encode([0u8; 32])),
                siblings: vec![],
            },
            height: 7,
            state_root: state_root.clone(),
            block_hash: "0xabc".into(),
            parent_state_root: "0xparent".into(),
            weight_used: 123,
            block: BlockHeader {
                tx_root: [9u8; 32],
                state_root: state_root.clone(),
            },
            finality: Some(Finality {
                height: 7,
                block_hash: "0xabc".into(),
                ep,
            }),
        };
        assert!(check_state_proof(&response(ep)).is_ok());
        assert!(matches!(
            verify_state_proof(&serde_json::to_string(&response(ep)).unwrap()),
            StateProofResult::Valid { height: 7, .. }
        ));
        assert!(
            check_state_proof(&response([0u8; 32]))
                .unwrap_err()
                .contains("execution proof")
        );
        let mut tampered = response(ep);
        tampered.proof.value = Some("0x01".into());
        assert!(matches!(
            verify_state_proof(&serde_json::to_string(&tampered).unwrap()),
            StateProofResult::Invalid { .. }
        ));
        assert!(
            check_state_proof(&tampered)
                .unwrap_err()
                .contains("merkle path")
        );
    }
}
