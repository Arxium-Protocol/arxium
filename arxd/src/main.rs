// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use tracing_subscriber::EnvFilter;

/// Used when `RUST_LOG` is unset. Targets are crate names (module paths), so
/// they must say `arxd_node`, not `node` — a wrong name silently matches nothing.
const DEFAULT_LOG_FILTER: &str = "warn,arxd_node=info,arxd_network=info,arxd_finality=info,\
arxd_genesis=info,arxd_runtime=info,xc_executor=info,xc_evidence=info,xc_rpc=info";

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // Diagnostics to stderr, data to stdout — the usual split, and load
        // bearing here: the key subcommands print a value meant to be captured
        // (`address=$(arxd validator-key ...)` in scripts/install.sh) or piped
        // (`arxd keys --json | jq`), and every one of them also logs. On stdout
        // those logs land inside the captured value, ANSI escapes and all.
        .with_writer(std::io::stderr)
        .init();
    arxd_node::run::<arxd_runtime::CoreChainRuntime>()
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_LOG_FILTER;

    #[test]
    fn default_log_filter_targets_are_workspace_crates() {
        let out = std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .output()
            .expect("cargo metadata");
        let meta = String::from_utf8(out.stdout).unwrap();
        for directive in DEFAULT_LOG_FILTER.split(',').filter(|d| d.contains('=')) {
            let target = directive.split('=').next().unwrap();
            let crate_name = target.replace('_', "-");
            assert!(
                meta.contains(&format!("\"name\":\"{crate_name}\"")),
                "log target {target} is not a workspace crate"
            );
        }
    }
}
