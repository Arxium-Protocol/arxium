// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Standalone evidence-artifact verifier. Depends only on `xc-artifact` — no
//! chain code, no storage, no network — so it builds and runs on a machine
//! that has never seen Arxium or the chain the evidence came from.
//!
//! Usage: `arx-verify <evidence.json>`. Prints a verdict; exits 0 if the
//! artifact is valid, 1 otherwise.

#[cfg(feature = "core-adjudicate")]
mod core_adjudicate;

use std::env;
use std::fs;
use std::process::ExitCode;

#[cfg(feature = "core-adjudicate")]
use xc_artifact::Fault;
use xc_artifact::{EvidenceArtifact, Verdict};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: arx-verify <evidence.json>");
        return ExitCode::FAILURE;
    };

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
