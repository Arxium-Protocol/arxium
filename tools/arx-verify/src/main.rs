// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Standalone evidence-artifact verifier. Depends only on `xc-artifact` — no
//! chain code, no storage, no network — so it builds and runs on a machine
//! that has never seen Arxium or the chain the evidence came from.
//!
//! Usage: `arx-verify <evidence.json>`. Prints a verdict; exits 0 if the
//! artifact is valid, 1 otherwise.
//!
//! `arx-verify state-proof <proof.json>` checks a `GET .../proof` response
//! from a node's RPC (a state key's value under a certified root) the same
//! way: the Merkle path against `state_root`, and `state_root` against the
//! finality certificate through the PoE commitment it signs over. What it
//! does *not* do is verify the certificate's BLS aggregate — that needs the
//! validator set's keys, which is the light-client trust root and out of
//! this tool's scope; it checks everything downstream of trusting the
//! certificate.

#[cfg(feature = "core-adjudicate")]
mod core_adjudicate;

use std::env;
use std::fs;
use std::process::ExitCode;

#[cfg(feature = "core-adjudicate")]
use xc_artifact::Fault;
use xc_artifact::{EvidenceArtifact, Verdict};

/// `GET /accounts/{address}/proof` et al. — the fields this tool checks.
/// Deliberately a subset: anything else in the response is informational.
#[derive(serde::Deserialize)]
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

#[derive(serde::Deserialize)]
struct BlockHeader {
    tx_root: [u8; 32],
    state_root: String,
}

#[derive(serde::Deserialize)]
struct Finality {
    height: u64,
    block_hash: String,
    ep: [u8; 32],
}

fn decode_root(root: &str) -> Result<[u8; 32], String> {
    hex::decode(root.strip_prefix("0x").unwrap_or(root))
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| format!("{root} is not a 32-byte root"))
}

fn check_state_proof(response: &StateProofResponse) -> Result<(), String> {
    let root = decode_root(&response.state_root)?;
    xc_artifact::verify_state_proof(root, &response.proof).map_err(|e| format!("merkle path: {e}"))?;
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

fn state_proof_main(path: &str) -> ExitCode {
    let response: StateProofResponse = match fs::read(path).map_err(|e| e.to_string()).and_then(|b| {
        serde_json::from_slice(&b).map_err(|e| e.to_string())
    }) {
        Ok(response) => response,
        Err(err) => {
            eprintln!("arx-verify: {path} is not a state-proof response: {err}");
            return ExitCode::FAILURE;
        }
    };
    match check_state_proof(&response) {
        Ok(()) => {
            println!("VALID");
            println!("key: {}", response.key);
            println!("height: {}", response.height);
            println!("block_hash: {}", response.block_hash);
            println!("value: {}", response.value);
            println!(
                "certified: {}",
                if response.finality.is_some() { "yes" } else { "genesis root, no certificate" }
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("INVALID: {err}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: arx-verify <evidence.json> | arx-verify state-proof <proof.json>");
        return ExitCode::FAILURE;
    };
    if path == "state-proof" {
        let Some(path) = args.next() else {
            eprintln!("usage: arx-verify state-proof <proof.json>");
            return ExitCode::FAILURE;
        };
        return state_proof_main(&path);
    }

    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("arx-verify: failed to read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let artifact: EvidenceArtifact = match serde_json::from_slice(&bytes) {
        Ok(artifact) => artifact,
        Err(err) => {
            eprintln!("arx-verify: {path} is not a valid evidence artifact: {err}");
            return ExitCode::FAILURE;
        }
    };

    match xc_artifact::verify(&artifact) {
        Ok(Verdict::Culpable { fault, culpable_pubkey }) => {
            println!("VALID");
            println!("fault: {fault}");
            println!("genesis_hash: {}", artifact.genesis_hash);
            println!("culpable_pubkey: {culpable_pubkey}");
            ExitCode::SUCCESS
        }
        Ok(Verdict::Disagreement { fault, parties }) => {
            // Structurally valid, but `xc_artifact::verify()` alone can only
            // confirm a genuine dispute exists, not who's at fault — see
            // `Fault::ExecutionDisagreement`/`Fault::ActionDivergence`'s doc
            // comments. With `core-adjudicate` enabled and an ActionDivergence
            // artifact in hand, try to actually resolve it by re-executing.
            #[cfg(feature = "core-adjudicate")]
            {
                let outcome = if matches!(artifact.fault, Fault::ActionDivergence { .. }) {
                    Some(core_adjudicate::adjudicate_action_divergence(&artifact))
                } else if matches!(artifact.fault, Fault::BlockDivergence { .. }) {
                    Some(core_adjudicate::adjudicate_block_divergence(&artifact))
                } else {
                    None
                };
                if let Some(outcome) = outcome {
                    match outcome {
                        Ok(core_adjudicate::AdjudicationOutcome::Culpable { culpable_pubkey }) => {
                            println!("VALID");
                            println!("fault: {fault}");
                            println!("genesis_hash: {}", artifact.genesis_hash);
                            println!("culpable_pubkey: {culpable_pubkey}");
                            return ExitCode::SUCCESS;
                        }
                        Ok(core_adjudicate::AdjudicationOutcome::Disagreement { reason }) => {
                            println!("UNRESOLVED");
                            println!("fault: {fault}");
                            println!("genesis_hash: {}", artifact.genesis_hash);
                            println!("parties: {}", parties.join(", "));
                            println!("note: {reason}");
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            println!("INVALID: {err}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }

            println!("UNRESOLVED");
            println!("fault: {fault}");
            println!("genesis_hash: {}", artifact.genesis_hash);
            println!("parties: {}", parties.join(", "));
            println!("note: this artifact proves a proposer/validator execution disagreement, not who is at fault");
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("INVALID: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod state_proof_tests {
    use super::*;

    /// A non-inclusion proof in an empty trie needs no siblings, so the
    /// whole check can be exercised without a node: the certificate binds
    /// the root through the EP, and a wrong EP is rejected.
    fn response(ep: [u8; 32]) -> StateProofResponse {
        let empty_root = xc_poe::state_trie::default_hashes()[256];
        let state_root = format!("0x{}", hex::encode(empty_root));
        StateProofResponse {
            key: "account:nobody".into(),
            value: serde_json::Value::Null,
            proof: xc_artifact::StateProof {
                key_hash: format!("0x{}", hex::encode(xc_poe::state_trie::hash_key(b"account:nobody"))),
                value: None,
                siblings_bitmap: format!("0x{}", hex::encode([0u8; 32])),
                siblings: vec![],
            },
            height: 7,
            state_root: state_root.clone(),
            block_hash: "0xabc".into(),
            parent_state_root: "0xparent".into(),
            weight_used: 123,
            block: BlockHeader { tx_root: [9u8; 32], state_root },
            finality: Some(Finality { height: 7, block_hash: "0xabc".into(), ep }),
        }
    }

    #[test]
    fn a_certificate_binds_the_root_through_the_ep() {
        let empty_root = xc_poe::state_trie::default_hashes()[256];
        let good = xc_poe::block_ep("0xparent", &[9u8; 32], &format!("0x{}", hex::encode(empty_root)), 123);
        assert!(check_state_proof(&response(good)).is_ok());
        let err = check_state_proof(&response([0u8; 32])).unwrap_err();
        assert!(err.contains("execution proof"), "{err}");
        let mut tampered = response(good);
        tampered.proof.value = Some("0x01".into());
        assert!(check_state_proof(&tampered).unwrap_err().contains("merkle path"));
    }
}
