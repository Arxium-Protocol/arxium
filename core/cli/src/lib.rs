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

impl Cli {
    pub fn into_config(self) -> NodeConfig {
        NodeConfig {
            base_path: self.base_path,
            port: self.port,
            is_validator: self.validator,
            rpc_token: self.rpc_token,
            rpc_bind: self.rpc_bind,
        }
    }
}
