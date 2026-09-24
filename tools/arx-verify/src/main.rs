// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use arx_verify::{EvidenceResult, StateProofResult};
use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(first) = args.next() else {
        eprintln!("usage: arx-verify <evidence.json> | arx-verify state-proof <proof.json>");
        return ExitCode::FAILURE;
    };
    let state_proof = first == "state-proof";
    let path = if state_proof {
        let Some(path) = args.next() else {
            eprintln!("usage: arx-verify state-proof <proof.json>");
            return ExitCode::FAILURE;
        };
        path
    } else {
        first
    };
    let json = match fs::read_to_string(&path) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("arx-verify: failed to read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    if state_proof {
        match arx_verify::verify_state_proof(&json) {
            StateProofResult::Valid {
                key,
                value,
                height,
                block_hash,
                certified,
            } => {
                println!(
                    "VALID\nkey: {key}\nheight: {height}\nblock_hash: {block_hash}\nvalue: {value}\ncertified: {certified}"
                );
                ExitCode::SUCCESS
            }
            StateProofResult::Invalid { error } => {
                println!("INVALID: {error}");
                ExitCode::FAILURE
            }
        }
    } else {
        match arx_verify::verify_evidence(&json) {
            EvidenceResult::Valid {
                fault,
                genesis_hash,
                culpable_pubkey,
            } => {
                println!(
                    "VALID\nfault: {fault}\ngenesis_hash: {genesis_hash}\nculpable_pubkey: {culpable_pubkey}"
                );
                ExitCode::SUCCESS
            }
            EvidenceResult::Unresolved {
                fault,
                genesis_hash,
                parties,
                note,
            } => {
                println!(
                    "UNRESOLVED\nfault: {fault}\ngenesis_hash: {genesis_hash}\nparties: {}\nnote: {note}",
                    parties.join(", ")
                );
                ExitCode::SUCCESS
            }
            EvidenceResult::Invalid { error, .. } => {
                println!("INVALID: {error}");
                ExitCode::FAILURE
            }
        }
    }
}
