// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! The sync protocol's request and response decode. A `SyncResponse` arrives
//! from whichever peer answered — including one this node dialed but does not
//! trust — and is decoded before anything in it is verified.
//!
//! Both directions are fuzzed from one target: a request is what a stranger
//! sends an exposed node, and cbor/bincode framing errors on either side are
//! the same class of bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xc_wire::{SyncRequest, SyncResponse};

type ChainBlock = xc_primitives::Block<arxd_runtime::ActionPayload>;

fuzz_target!(|data: &[u8]| {
    let _ = xc_primitives::decode_wire_canonical::<SyncRequest>(data);
    let _ = xc_primitives::decode_wire_canonical::<SyncResponse<ChainBlock>>(data);
});
