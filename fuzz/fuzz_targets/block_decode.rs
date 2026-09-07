// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The gossip/sync block decode, on attacker-supplied bytes.
//!
//! This is the exact call `arxd/network`'s `decode_wire` makes on every
//! gossiped block before any signature is checked. `wire_config()`'s size
//! limit is a ceiling on how much a declared length can allocate — it is not
//! a proof that the decode path behaves on malformed input, and Track B put
//! attacker-declared lengths throughout this format.
//!
//! A finding here is a panic, an abort, or an OOM. Decoding to `Err` is the
//! expected outcome for almost every input and is not a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

type ChainBlock = xc_primitives::Block<arxd_runtime::ActionPayload>;

fuzz_target!(|data: &[u8]| {
    let _ = xc_primitives::decode_wire_canonical::<ChainBlock>(data);
});
