// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use xc_primitives::NodeConfig;

/// Flags accepted with no subcommand — runs the node, same as always
/// (`arxd --validator ...`). `arxd node-key` is the only other subcommand.
#[derive(Parser, Clone, Debug)]
#[command(about = "Arxium chain node")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Load (or, on first run, generate) this node's libp2p identity key and
    /// print its PeerId, without starting the node — lets an operator learn
    /// their node's network identity to hand to peers ahead of time.
    NodeKey {
        #[arg(long, default_value_os_t = default_base_path())]
        base_path: PathBuf,
    },
    /// Load (or, on first run, generate) this node's validator signing key and
    /// print its address, without starting the node. That address has to be in
    /// the chain spec's validator set (or get added later via `JoinValidator`)
    /// or this node never produces a block and never says why — printing it is
    /// the only way to check before starting. See `docs/runbook.md`.
    ValidatorKey {
        #[arg(long, env = "ARXD_BASE_PATH", default_value_os_t = default_base_path())]
        base_path: PathBuf,
    },

    /// Load (or, on first run, generate) this node's BLS finality-signing key
    /// and print its pubkey (hex), without starting the node — hand this to
    /// `send-tx --action register-bls-key` so this validator's precommit
    /// votes count toward finality quorum.
    BlsKey {
        #[arg(long, default_value_os_t = default_base_path())]
        base_path: PathBuf,
        /// Also render the pubkey as a terminal QR code, for a client that
        /// scans it instead of copying hex by hand.
        #[arg(long)]
        qr: bool,
    },
    /// Authorizes an operator wallet (e.g. the app) to submit
    /// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey`/staking actions on
    /// this validator's behalf, without this validator's signing key ever
    /// leaving this machine. Shows a QR code the app scans; once the app
    /// reports back which address to authorize, this signs and submits
    /// `AuthorizeOperator` itself. See `--revoke` to remove the current
    /// operator instead (no scanning needed).
    Pair {
        #[arg(long, default_value_os_t = default_base_path())]
        base_path: PathBuf,
        /// RPC address of a node reachable both by this command and by the
        /// app (typically the same gateway the app already submits actions
        /// through) — not necessarily this validator's own node's RPC. The
        /// pairing session lives only in that node process's memory
        /// (`core/rpc`'s `PairingStore`), so this must match whatever
        /// `NODE_RPC_URL` the app's backend is configured with, or the app
        /// polls a node that never saw this session and reports it as
        /// expired. Falls back to `$ARXD_NODE` so that doesn't have to be
        /// retyped every run.
        #[arg(long, env = "ARXD_NODE", default_value = "127.0.0.1:30333")]
        node: String,
        /// Sent as "Authorization: Bearer <token>" if that node requires
        /// one. Falls back to `$ARXD_RPC_TOKEN`.
        #[arg(long, env = "ARXD_RPC_TOKEN")]
        token: Option<String>,
        /// Revoke the current operator instead of pairing a new one.
        #[arg(long)]
        revoke: bool,
    },
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    #[arg(long, env = "ARXD_BASE_PATH", default_value_os_t = default_base_path())]
    pub base_path: PathBuf,

    #[arg(long, env = "ARXD_PORT", default_value_t = 30333)]
    pub port: u16,

    /// Port for the P2P (libp2p) TCP + QUIC listener.
    #[arg(long, env = "ARXD_P2P_PORT", default_value_t = 30334)]
    pub p2p_port: u16,

    /// Explicit peer multiaddrs to dial on startup (e.g.
    /// /ip4/1.2.3.4/tcp/30334/p2p/12D3Koo...), comma-separated. Discovery
    /// beyond same-LAN mDNS. If empty, falls back to the chain spec's
    /// `boot_nodes` list (e.g. `devnet.json`) — same role as a Polkadot
    /// chain-spec's `bootNodes`.
    #[arg(long, env = "ARXD_BOOTNODES", value_delimiter = ',')]
    pub bootnodes: Vec<String>,

    /// DEVNET ONLY — use the well-known, seed-pinned network identity other
    /// nodes' default `--bootnodes` value points at, instead of generating a
    /// random one. Run exactly one node with this flag per devnet.
    ///
    /// As an env var this takes an explicit `true`/`false` rather than
    /// presence alone, so `scripts/install.sh`'s generated env file can
    /// carry every key with a value — including the off ones — instead of
    /// commenting lines in and out. See `bool_env_vars_need_an_explicit_value`.
    #[arg(long, env = "ARXD_BOOTNODE", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = clap::ArgAction::Set)]
    pub bootnode: bool,

    #[arg(long, env = "ARXD_VALIDATOR", num_args = 0..=1, default_missing_value = "true", default_value_t = false, action = clap::ArgAction::Set)]
    pub validator: bool,

    /// If set, the RPC server requires `Authorization: Bearer <token>` on every request.
    #[arg(long, env = "ARXD_RPC_TOKEN")]
    pub rpc_token: Option<String>,

    /// Address the RPC server binds to. Defaults to loopback-only; put a TLS-
    /// terminating reverse proxy in front for production, or pass 0.0.0.0 to
    /// accept connections directly (devnet/LAN convenience).
    #[arg(long, env = "ARXD_RPC_BIND", default_value = "127.0.0.1")]
    pub rpc_bind: String,
}

fn default_base_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".arxium")
}

impl RunArgs {
    pub fn into_config(self) -> NodeConfig {
        NodeConfig {
            base_path: self.base_path,
            port: self.port,
            p2p_port: self.p2p_port,
            // Empties are dropped here, at the one place NodeConfig is built,
            // rather than at either consumer. `arxd/node` treats an empty
            // `bootnodes` as "fall back to the chain spec's boot_nodes", while
            // `arxd/network` separately filters empty strings out of whatever
            // it's handed — so a blank `ARXD_BOOTNODES=` (which clap's
            // `value_delimiter` turns into `[""]`, not `[]`) used to read as
            // "an explicit bootnode list" to the first and "no peers at all" to
            // the second, silently skipping the chain spec and joining nothing.
            // Also covers `--bootnodes a,,b`. See `blank_bootnodes_env_is_no_bootnodes`.
            bootnodes: self
                .bootnodes
                .into_iter()
                .filter(|addr| !addr.trim().is_empty())
                .collect(),
            is_bootnode: self.bootnode,
            is_validator: self.validator,
            rpc_token: self.rpc_token,
            rpc_bind: self.rpc_bind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// `--validator` and `--bootnode` are `ArgAction::Set` rather than clap's
    /// default `SetTrue` for a bool, so that an env var can turn them *off*
    /// as well as on. With `SetTrue`, clap treats the env var's mere presence
    /// as true, which would make `ARXD_VALIDATOR=false` in the env file
    /// generated by `scripts/install.sh` start a validator — the opposite of
    /// what the line says. This test is what stops that regressing.
    /// `scripts/install.sh` writes every key into the generated env file,
    /// including `ARXD_BOOTNODES=` with no value, so that the file documents
    /// what's configurable. That blank has to mean "no explicit bootnodes" —
    /// otherwise `arxd/node` sees a non-empty list, skips the chain spec's
    /// `boot_nodes` fallback, and the node joins nothing at all.
    #[test]
    fn blank_bootnodes_env_is_no_bootnodes() {
        let cfg = Cli::try_parse_from(["arxd", "--bootnodes", ""])
            .unwrap()
            .run
            .into_config();
        assert!(cfg.bootnodes.is_empty(), "blank must fall back to the chain spec");

        let cfg = Cli::try_parse_from(["arxd", "--bootnodes", "/ip4/1.2.3.4/tcp/30334,,/ip4/5.6.7.8/tcp/30334"])
            .unwrap()
            .run
            .into_config();
        assert_eq!(cfg.bootnodes.len(), 2, "a stray comma must not add an empty entry");
    }

    #[test]
    fn bool_env_vars_need_an_explicit_value() {
        // Bare flag still works, and is still the documented CLI form.
        let cli = Cli::try_parse_from(["arxd", "--validator"]).unwrap();
        assert!(cli.run.validator);

        // Absent everywhere: off.
        let cli = Cli::try_parse_from(["arxd"]).unwrap();
        assert!(!cli.run.validator);
        assert!(!cli.run.bootnode);

        // Env vars are process-global, so all the env assertions live in this
        // one test rather than racing each other across parallel tests.
        unsafe {
            std::env::set_var("ARXD_VALIDATOR", "false");
            std::env::set_var("ARXD_BOOTNODE", "false");
        }
        let cli = Cli::try_parse_from(["arxd"]).unwrap();
        assert!(!cli.run.validator, "ARXD_VALIDATOR=false must not enable it");
        assert!(!cli.run.bootnode, "ARXD_BOOTNODE=false must not enable it");

        unsafe { std::env::set_var("ARXD_VALIDATOR", "true") }
        let cli = Cli::try_parse_from(["arxd"]).unwrap();
        assert!(cli.run.validator);

        // An explicit flag still beats the env var, so an operator can
        // override the installed env file for a one-off run.
        unsafe { std::env::set_var("ARXD_VALIDATOR", "false") }
        let cli = Cli::try_parse_from(["arxd", "--validator"]).unwrap();
        assert!(cli.run.validator, "explicit flag must win over the env file");

        unsafe {
            std::env::remove_var("ARXD_VALIDATOR");
            std::env::remove_var("ARXD_BOOTNODE");
        }
    }
}
