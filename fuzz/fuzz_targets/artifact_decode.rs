// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Evidence artifacts: JSON parse plus `verify()`.
//!
//! An artifact is submitted by whoever wants someone slashed, so it is
//! attacker-controlled by construction, and `verify()` does the hex decoding,
//! length checks and signature parsing on fields the submitter chose. Fuzzed
//! as UTF-8 text since that is how one actually arrives (`artifact_json` in
//! `SubmitExecutionFault`, and the files under the evidence directory).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(artifact) = serde_json::from_str::<xc_artifact::EvidenceArtifact>(text) else {
        return;
    };
    let _ = xc_artifact::verify(&artifact);
});
