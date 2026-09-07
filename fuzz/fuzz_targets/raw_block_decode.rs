// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `RawBlock`/`RawAction` — the payload-agnostic decode an external indexer
//! (Retracer) runs on every block, including ones carrying action kinds it
//! has never heard of. Its whole job is to be tolerant of input it doesn't
//! understand, which is exactly the shape that hides parser bugs.
//!
//! The property asserted is the one the two repos depend on: for bytes that
//! decode both ways, a tolerant reader's `RawBlock::hash()` must equal the
//! node's own `Block::hash()`. If those ever diverge, an indexer silently
//! indexes blocks under hashes that exist nowhere on chain — the same class
//! of drift bug as the mirrored-enum one Track B removed, and just as quiet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xc_primitives::{Block, RawBlock, decode_wire_canonical};

type ChainBlock = Block<arxd_runtime::ActionPayload>;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = decode_wire_canonical::<RawBlock>(data) else {
        return;
    };
    let raw_hash = raw.hash();

    if let Ok(block) = decode_wire_canonical::<ChainBlock>(data) {
        assert_eq!(
            raw_hash,
            block.hash(),
            "RawBlock and Block disagree on the hash of the same wire bytes"
        );
    }
});
