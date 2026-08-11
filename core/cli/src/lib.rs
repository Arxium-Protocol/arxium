use clap::Parser;
use std::path::PathBuf;
use xc_primitives::NodeConfig;

#[derive(Parser, Clone, Debug)]
#[command(about = "Arxium chain node")]
pub struct Cli {
    #[arg(long, default_value_os_t = default_base_path())]
    pub base_path: PathBuf,

    #[arg(long, default_value_t = 30333)]
    pub port: u16,

    /// Port for the P2P (libp2p) TCP + QUIC listener.
    #[arg(long, default_value_t = 30334)]
    pub p2p_port: u16,

    /// Explicit peer multiaddrs to dial on startup (e.g.
    /// /ip4/1.2.3.4/tcp/30334/p2p/12D3Koo...), comma-separated. Discovery
    /// beyond same-LAN mDNS. Defaults to the well-known devnet bootnode
    /// (see `--bootnode`) on localhost; pass `--bootnodes ""` to disable.
    #[arg(long, value_delimiter = ',', default_value = DEFAULT_BOOTNODE)]
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

// PeerId that `xc_network::identity::DEVNET_BOOTNODE_SEED` produces, and the
// default `--p2p-port` above — this is where a `--bootnode` node listens.
const DEFAULT_BOOTNODE: &str =
    "/ip4/127.0.0.1/tcp/30334/p2p/12D3KooWHP2Ve7tpkRQMJACbU4xmq9aDwL6gphLRHLJ3xB6nU5KA";

fn default_base_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".arxium")
}

impl Cli {
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
