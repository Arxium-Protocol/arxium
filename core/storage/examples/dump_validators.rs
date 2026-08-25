// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

// Diagnostic: dumps every point where the round-robin validator set changed,
// so a WrongProposer rejection during sync can be traced back to which
// height a JoinValidator took effect at.
//
// Usage: cargo run -p xc-storage --example dump_validators -- <data-dir>
use std::path::PathBuf;
use xc_storage::ArxiumDb;

fn main() {
    let data_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: dump_validators <data-dir>"),
    );

    let db = ArxiumDb::open(&data_dir).unwrap();
    let tip = db.get_tip_height().unwrap().unwrap_or(0);
    println!("local tip: {tip}");

    let mut prev: Vec<String> = vec![];
    for h in 0..=tip {
        let set: Vec<String> = db
            .get_validator_set_at(h)
            .unwrap()
            .into_iter()
            .map(|a| a.to_string())
            .collect();
        if set != prev {
            println!("validator_set_at({h}) changed -> {set:?}");
            prev = set;
        }
    }
}
