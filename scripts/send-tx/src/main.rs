// ponytail: testing-only tool for a local devnet. Raw std::net HTTP instead of
// pulling in an HTTP client crate; devnet-keys.json instead of a real wallet.
use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use node::payload::{ActionPayload, ChainAction};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use xc_primitives::Address;

/// Signs and submits a Transfer action to a running arxd node. Devnet testing only.
#[derive(Parser)]
struct Args {
    /// Sender: a name from devnet-keys.json (e.g. "alice"), or a raw hex ed25519 seed
    #[arg(long)]
    from: String,

    /// Recipient: a name from devnet-keys.json, or a bech32 address
    #[arg(long)]
    to: String,

    #[arg(long)]
    amount: u128,

    /// Override the auto-fetched nonce
    #[arg(long)]
    nonce: Option<u64>,

    #[arg(long, default_value = "127.0.0.1:30333")]
    node: String,
}

fn keys_file() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../arxd/node/specs/devnet-keys.json"
    );
    let raw = std::fs::read_to_string(path).expect("read devnet-keys.json");
    serde_json::from_str(&raw).expect("parse devnet-keys.json")
}

fn resolve_signer(name: &str, keys: &Value) -> Result<SigningKey> {
    let seed_hex = match keys.get(name) {
        Some(entry) => entry["ed25519_seed_hex"]
            .as_str()
            .with_context(|| format!("no seed for {name} in devnet-keys.json"))?
            .to_string(),
        None => name.to_string(),
    };
    let seed = hex::decode(&seed_hex)
        .context("--from is not a name in devnet-keys.json or a hex seed")?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn resolve_address(name: &str, keys: &Value) -> Result<Address> {
    match keys.get(name) {
        Some(entry) => {
            let addr = entry["address"]
                .as_str()
                .with_context(|| format!("no address for {name} in devnet-keys.json"))?;
            Address::parse(addr).context("bad address in devnet-keys.json")
        }
        None => Address::parse(name)
            .context("--to is not a name in devnet-keys.json or a valid address"),
    }
}

// Minimal HTTP/1.1 client: local testing only, plain text responses with Content-Length.
fn http(method: &str, node: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect(node).with_context(|| format!("connect to {node}"))?;
    let body = body.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {node}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let (head, rest) = response
        .split_once("\r\n\r\n")
        .context("malformed HTTP response")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .context("malformed status line")?;
    Ok((status, rest.to_string()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let keys = keys_file();

    let signer = resolve_signer(&args.from, &keys)?;
    let sender = resolve_address(&args.from, &keys)?;
    let to = resolve_address(&args.to, &keys)?;

    let nonce = match args.nonce {
        Some(n) => n,
        None => {
            let (status, body) = http("GET", &args.node, &format!("/accounts/{sender}"), None)?;
            if status != 200 {
                bail!("GET /accounts/{sender} -> {status}: {body}");
            }
            serde_json::from_str::<Value>(&body)?["nonce"]
                .as_u64()
                .context("account response missing nonce")?
        }
    };

    let mut action = ChainAction {
        sender,
        nonce,
        signature: None,
        payload: ActionPayload::Transfer {
            to,
            amount: args.amount,
        },
    };
    let signature = signer.sign(&action.signing_bytes());
    action.signature = Some(hex::encode(signature.to_bytes()));

    let payload = serde_json::to_string(&action)?;
    println!("submitting: {payload}");
    let (status, body) = http("POST", &args.node, "/actions", Some(&payload))?;
    println!("-> {status} {body}");
    if status != 202 {
        bail!("node rejected the action");
    }
    Ok(())
}
