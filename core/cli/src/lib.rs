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
        /// through) — not necessarily this validator's own node's RPC.
        #[arg(long, default_value = "127.0.0.1:30333")]
        node: String,
        /// Sent as "Authorization: Bearer <token>" if that node requires one.
        #[arg(long)]
        token: Option<String>,
        /// Revoke the current operator instead of pairing a new one.
        #[arg(long)]
        revoke: bool,
    },
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    #[arg(long, default_value_os_t = default_base_path())]
    pub base_path: PathBuf,

    #[arg(long, default_value_t = 30333)]
    pub port: u16,

    /// Port for the P2P (libp2p) TCP + QUIC listener.
    #[arg(long, default_value_t = 30334)]
    pub p2p_port: u16,

    /// Explicit peer multiaddrs to dial on startup (e.g.
    /// /ip4/1.2.3.4/tcp/30334/p2p/12D3Koo...), comma-separated. Discovery
    /// beyond same-LAN mDNS. If empty, falls back to the chain spec's
    /// `boot_nodes` list (e.g. `devnet.json`) — same role as a Polkadot
    /// chain-spec's `bootNodes`.
    #[arg(long, value_delimiter = ',')]
    pub bootnodes: Vec<String>,

    /// DEVNET ONLY — use the well-known, seed-pinned network identity other
    /// nodes' default `--bootnodes` value points at, instead of generating a
    /// random one. Run exactly one node with this flag per devnet.
    #[arg(long)]
    pub bootnode: bool,

    #[arg(long)]
    pub validator: bool,

    /// If set, the RPC server requires `Authorization: Bearer <token>` on every request.
    #[arg(long)]
    pub rpc_token: Option<String>,

    /// Address the RPC server binds to. Defaults to loopback-only; put a TLS-
    /// terminating reverse proxy in front for production, or pass 0.0.0.0 to
    /// accept connections directly (devnet/LAN convenience).
    #[arg(long, default_value = "127.0.0.1")]
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
            bootnodes: self.bootnodes,
            is_bootnode: self.bootnode,
            is_validator: self.validator,
            rpc_token: self.rpc_token,
            rpc_bind: self.rpc_bind,
        }
    }
}
