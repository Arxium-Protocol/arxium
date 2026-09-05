// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Re-exports `arxd_runtime::adjudicate` — the payload-aware re-execution
//! adjudicator lives there now, not here, since `SubmitExecutionFault`
//! dispatch needs the exact same replay logic on-chain and `arx-verify`
//! depends on `arxd-runtime` (never the reverse), so relocating avoids a
//! circular dependency and a second copy of the code. This module exists
//! purely so `main.rs`'s existing `core_adjudicate::` call sites, gated
//! behind the same `core-adjudicate` feature, keep compiling unchanged.

pub use arxd_runtime::adjudicate::*;
