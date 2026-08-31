// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Standalone evidence-artifact verifier. Depends only on `xc-artifact` — no
//! chain code, no storage, no network — so it builds and runs on a machine
//! that has never seen Arxium or the chain the evidence came from.
//!
//! Usage: `arx-verify <evidence.json>`. Prints a verdict; exits 0 if the
//! artifact is valid, 1 otherwise.

use std::env;
use std::fs;
use std::process::ExitCode;

use xc_artifact::EvidenceArtifact;

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
        Ok(verdict) => {
            println!("VALID");
            println!("fault: {}", verdict.fault);
            println!("genesis_hash: {}", artifact.genesis_hash);
            println!("culpable_pubkey: {}", verdict.culpable_pubkey);
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("INVALID: {err}");
            ExitCode::FAILURE
        }
    }
}
