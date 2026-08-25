// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let filter_level =
        EnvFilter::new("warn,node=debug,xc_storage=debug,xc_primitives=debug,network=debug");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| filter_level);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    node::run()
}
