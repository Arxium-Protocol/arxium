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

/// Signs and submits an action to a running arxd node. Devnet testing only.
#[derive(Parser)]
struct Args {
    /// Sender: a name from devnet-keys.json (e.g. "alice"), or a raw hex ed25519 seed
    #[arg(long)]
    from: String,

    /// "transfer" (default), "join-validator", "leave-validator", "stake", "unstake",
    /// "register-bls-key", or "sub-account" (prints a validator's stake
    /// sub-account address, submits nothing)
    #[arg(long, default_value = "transfer")]
    action: String,

    /// Recipient: a name from devnet-keys.json, or a bech32 address. Required for "transfer".
    #[arg(long)]
    to: Option<String>,

    /// Required for "transfer".
    #[arg(long)]
    amount: Option<u128>,

    /// Stake to bond, bookkeeping-only for now. Required for "join-validator".
    #[arg(long)]
    stake: Option<u128>,

    /// Validator address (name from devnet-keys.json, or bech32 address). Required for "stake"/"unstake".
    #[arg(long)]
    validator: Option<String>,

    /// BLS pubkey, hex-encoded (from `arxd bls-key`). Required for "register-bls-key".
    #[arg(long)]
    bls_pubkey: Option<String>,

    /// Override the auto-fetched nonce
    #[arg(long)]
    nonce: Option<u64>,

    #[arg(long, default_value = "127.0.0.1:30333")]
    node: String,

    /// Sent as "Authorization: Bearer <token>" — required once the node runs with --rpc-token.
    #[arg(long)]
    token: Option<String>,
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
fn http(method: &str, node: &str, path: &str, body: Option<&str>, token: Option<&str>) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect(node).with_context(|| format!("connect to {node}"))?;
    let body = body.unwrap_or_default();
    let auth_header = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {node}\r\nConnection: close\r\nContent-Type: application/json\r\n{auth_header}Content-Length: {}\r\n\r\n{body}",
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

    // Not a real action — just prints the deterministic stake sub-account
    // address for a validator, so `GET /accounts/{addr}` can check what
    // actually landed on-chain after a stake/unstake/slash.
    if args.action == "sub-account" {
        let validator = resolve_address(
            args.validator.as_deref().context("--validator is required for sub-account")?,
            &keys,
        )?;
        println!("{}", circuit_staking::stake_subaccount(&validator));
        return Ok(());
    }

    let signer = resolve_signer(&args.from, &keys)?;
    // --from a name uses the keys file's recorded address; --from a raw seed
    // has no such entry, so derive the address from the key itself (the same
    // derivation validator.rs uses) instead of bech32-parsing the seed.
    let sender = if keys.get(&args.from).is_some() {
        resolve_address(&args.from, &keys)?
    } else {
        Address::from_pubkey_bytes(signer.verifying_key().as_bytes())
            .context("failed to derive address from --from seed")?
    };

    let action_payload = match args.action.as_str() {
        "transfer" => ActionPayload::Transfer {
            to: resolve_address(
                args.to.as_deref().context("--to is required for transfer")?,
                &keys,
            )?,
            amount: args.amount.context("--amount is required for transfer")?,
        },
        "join-validator" => ActionPayload::JoinValidator {
            stake: args.stake.context("--stake is required for join-validator")?,
        },
        "leave-validator" => ActionPayload::LeaveValidator,
        "stake" => ActionPayload::Stake {
            validator: resolve_address(
                args.validator.as_deref().context("--validator is required for stake")?,
                &keys,
            )?,
            amount: args.amount.context("--amount is required for stake")?,
        },
        "unstake" => ActionPayload::Unstake {
            validator: resolve_address(
                args.validator.as_deref().context("--validator is required for unstake")?,
                &keys,
            )?,
            amount: args.amount.context("--amount is required for unstake")?,
        },
        "register-bls-key" => ActionPayload::RegisterBlsKey {
            pubkey: hex::decode(
                args.bls_pubkey.as_deref().context("--bls-pubkey is required for register-bls-key")?,
            )
            .context("--bls-pubkey is not valid hex")?,
        },
        other => {
            bail!(
                "unknown --action {other:?}, expected transfer, join-validator, leave-validator, stake, unstake, or register-bls-key"
            )
        }
    };

    let nonce = match args.nonce {
        Some(n) => n,
        None => {
            let (status, body) = http("GET", &args.node, &format!("/accounts/{sender}"), None, args.token.as_deref())?;
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
        payload: action_payload,
    };
    let signature = signer.sign(&action.signing_bytes());
    action.signature = Some(hex::encode(signature.to_bytes()));

    let payload = serde_json::to_string(&action)?;
    println!("submitting: {payload}");
    let (status, body) = http("POST", &args.node, "/actions", Some(&payload), args.token.as_deref())?;
    println!("-> {status} {body}");
    if status != 202 {
        bail!("node rejected the action");
    }
    Ok(())
}
