// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Startup guard for the `fault-injection` build's harness knobs. Every knob
//! refuses to arm outside the harness chain, and says loudly when it is armed.

use anyhow::Result;
use tracing::warn;

/// The one `chain_name` a fault-injection build is allowed to arm on. Not
/// the built-in `--chain devnet` preset — that preset's spec (`devnet.json`)
/// names itself `"corechain"` and its `boot_nodes` point at real public
/// IPs, so it's a shared network, not a local sandbox. A harness chain spec
/// must set `"chain_name": "arxium-fault-injection-harness"` explicitly, so
/// a mistyped `--chain` or a copy-pasted systemd unit can't ever satisfy
/// this by accident — anywhere else, this flag wouldn't be a test, it would
/// be a validator lying about its own state to real peers.
const FAULT_INJECTION_CHAIN_NAME: &str = "arxium-fault-injection-harness";

fn ensure_fault_injection_allowed(chain_name: &str) -> Result<()> {
    anyhow::ensure!(
        chain_name == FAULT_INJECTION_CHAIN_NAME,
        "fault injection requires chain_name {FAULT_INJECTION_CHAIN_NAME:?}, refusing to start on {chain_name:?}"
    );
    Ok(())
}

/// Env-var knobs: `(variable, validator, warning)`. Each is read by the
/// subsystem it affects; this table only decides whether the process may
/// boot with it set. The validator returns a complaint if the value is
/// unreadable.
type Validate = fn() -> Option<String>;
const ENV_KNOBS: &[(&str, Validate, &str)] = &[
    // Makes a validator refuse to talk to named peers, which outside a
    // harness is just a node silently cutting itself off from the network.
    // `build_swarm` reads it (arxd/network's `partitioned_block_list`),
    // which also validates the peer list.
    (
        "ARXD_BLOCK_PEERS",
        || None,
        "PARTITION ARMED — this node refuses all connections to these peers.",
    ),
    // Slowing the round timeout down is how the partition harness makes its
    // heal-during-voting window deterministic (arxd/finality's
    // `round_timeout`); on a real chain it would just be a validator that
    // tolerates a stalled round far longer than its peers do.
    //
    // Validated here, on the main thread, so a typo refuses to boot. The
    // value is read lazily by a thread `spawn_finality` spawns, where
    // rejecting it is not an option: a panic there unwinds that thread
    // alone (no panic hook, no `panic = "abort"`), leaving a node that
    // still produces and gossips but has silently stopped voting and
    // tallying.
    (
        "ARXD_ROUND_TIMEOUT_SECS",
        arxd_finality::round_timeout_override_error,
        "ROUND TIMEOUT OVERRIDDEN — this node waits this long before voting to advance a round.",
    ),
    // Makes the node a Byzantine proposer (arxd/network's `withhold`,
    // arxd/finality's `withheld_height`). The peer list is validated where
    // it is parsed, in `run_swarm`.
    (
        "ARXD_WITHHOLD_BLOCK_AT_HEIGHT",
        arxd_finality::withheld_height_error,
        "WITHHOLDING PROPOSER ARMED — this node will not gossip or vote on its block at this height.",
    ),
];

/// Arms `--inject-fault-at-height` and checks every set env knob. Call once
/// at boot, before any block is produced.
pub(crate) fn check_startup(chain_name: &str, inject_fault_at_height: Option<u64>) -> Result<()> {
    if let Some(height) = inject_fault_at_height {
        ensure_fault_injection_allowed(chain_name)?;
        crate::produce::INJECT_FAULT_AT_HEIGHT
            .set(height)
            .expect("set exactly once, before any block is produced");
        warn!(
            height,
            "FAULT INJECTION ARMED — this node will corrupt its own state_root when it \
             produces this height. Never use outside a devnet acceptance test."
        );
    }
    for (var, validate, warning) in ENV_KNOBS {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        ensure_fault_injection_allowed(chain_name)?;
        if let Some(err) = validate() {
            anyhow::bail!(err);
        }
        warn!(%var, %value, "{warning} Never use outside a devnet acceptance test.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FAULT_INJECTION_CHAIN_NAME, check_startup, ensure_fault_injection_allowed};

    #[test]
    fn check_startup_refuses_the_fault_flag_off_the_harness_chain() {
        assert!(check_startup("corechain", Some(5)).is_err());
        assert!(crate::produce::INJECT_FAULT_AT_HEIGHT.get().is_none());
    }

    #[test]
    fn the_harness_chain_name_is_allowed() {
        assert!(ensure_fault_injection_allowed(FAULT_INJECTION_CHAIN_NAME).is_ok());
    }

    #[test]
    fn anything_else_is_refused_including_the_real_devnet_preset() {
        assert!(ensure_fault_injection_allowed("mainnet").is_err());
        assert!(ensure_fault_injection_allowed("").is_err());
        // devnet.json's actual chain_name — must never pass.
        assert!(ensure_fault_injection_allowed("corechain").is_err());
    }
}
