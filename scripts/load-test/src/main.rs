// ponytail: devnet load-testing tool, same shape as scripts/send-tx (raw
// std::net HTTP, devnet-keys.json instead of a real wallet). Single-threaded
// pacing loop rather than a thread pool: the RPC layer's rate limiter
// (core/rpc: 60 req/60s) is keyed per client IP, not per connection, so
// concurrency from one machine can't buy more throughput than pacing does —
// it would just add complexity for nothing.
use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use node::payload::ActionPayload;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use xc_primitives::{Action, Address};

/// Fires signed transfer actions at a running arxd node to measure real
/// submit->accept->confirm throughput and latency. Devnet testing only.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:30333")]
    node: String,

    #[arg(long)]
    token: Option<String>,

    /// Target requests/sec, paced with a sleep between sends. The RPC
    /// layer's rate limit is 60/60s per IP — pass a higher --rate to find
    /// out how much of that limit this run actually consumes.
    #[arg(long, default_value_t = 1.0)]
    rate: f64,

    /// How long to run the paced phase.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,

    /// Skip pacing and fire this many requests back-to-back instead, to
    /// verify the rate limiter itself holds under a burst. Overrides
    /// --rate/--duration-secs when set.
    #[arg(long)]
    burst: Option<u64>,
}

fn keys_file() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../arxd/node/specs/devnet-keys.json"
    );
    let raw = std::fs::read_to_string(path).expect("read devnet-keys.json");
    serde_json::from_str(&raw).expect("parse devnet-keys.json")
}

fn signer(name: &str, keys: &Value) -> SigningKey {
    let seed_hex = keys[name]["ed25519_seed_hex"].as_str().expect("seed in devnet-keys.json");
    let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed)
}

fn address(name: &str, keys: &Value) -> Address {
    Address::parse(keys[name]["address"].as_str().expect("address in devnet-keys.json")).unwrap()
}

fn http(node: &str, path: &str, body: Option<&str>, token: Option<&str>) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect(node).with_context(|| format!("connect to {node}"))?;
    let body = body.unwrap_or_default();
    let auth_header = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let method = if body.is_empty() { "GET" } else { "POST" };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {node}\r\nConnection: close\r\nContent-Type: application/json\r\n{auth_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, rest) = response.split_once("\r\n\r\n").context("malformed HTTP response")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .context("malformed status line")?;
    Ok((status, rest.to_string()))
}

/// `Ok(None)` means "ask again later" (429 — the read shares the same per-IP
/// budget as submission, so a burst can starve its own confirmation polling)
/// as distinct from a hard failure.
fn get_nonce(node: &str, addr: &Address, token: Option<&str>) -> Result<Option<u64>> {
    let (status, body) = http(node, &format!("/accounts/{addr}"), None, token)?;
    if status == 429 {
        return Ok(None);
    }
    if status != 200 {
        anyhow::bail!("GET /accounts/{addr} -> {status}: {body}");
    }
    Ok(Some(serde_json::from_str::<Value>(&body)?["nonce"].as_u64().unwrap_or(0)))
}

// Startup only, well under the rate limit — a bare retry is fine here,
// unlike the confirm loop below.
fn get_nonce_retrying(node: &str, addr: &Address, token: Option<&str>) -> Result<u64> {
    loop {
        if let Some(n) = get_nonce(node, addr, token)? {
            return Ok(n);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

struct Outcome {
    status: u16,
    latency: Duration,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let keys = keys_file();

    // Round-robin senders so each request uses a fresh, locally-tracked
    // nonce instead of waiting on the previous one to confirm — this is
    // what actually lets the paced loop keep up with --rate.
    let senders = ["alice", "bob", "charlie"];
    let signers: Vec<SigningKey> = senders.iter().map(|n| signer(n, &keys)).collect();
    let addrs: Vec<Address> = senders.iter().map(|n| address(n, &keys)).collect();
    let mut nonces: Vec<u64> = addrs
        .iter()
        .map(|a| get_nonce_retrying(&args.node, a, args.token.as_deref()))
        .collect::<Result<_>>()?;

    let target_count = args.burst.unwrap_or_else(|| {
        (args.rate * args.duration_secs as f64).round() as u64
    });
    let interval = args.burst.is_none().then(|| Duration::from_secs_f64(1.0 / args.rate.max(0.001)));

    println!(
        "sending {target_count} action(s) against {} ({})",
        args.node,
        args.burst.map(|_| "burst, unpaced".to_string()).unwrap_or_else(|| format!("paced at {:.2}/s", args.rate)),
    );

    let mut outcomes = Vec::with_capacity(target_count as usize);
    let run_start = Instant::now();
    for i in 0..target_count {
        let sender_idx = i as usize % senders.len();
        let to_idx = (sender_idx + 1) % senders.len();
        // Only advances on actual acceptance below — bumping it
        // unconditionally would leave a nonce gap behind every rejected
        // send (429, bad signature, whatever), and the chain can never
        // execute anything a sender submits after a gap it never fills.
        let nonce = nonces[sender_idx];

        let mut action = Action {
            sender: addrs[sender_idx].clone(),
            nonce,
            signature: None,
            payload: ActionPayload::Transfer { to: addrs[to_idx].clone(), amount: 1 },
        };
        let signature = signers[sender_idx].sign(&action.signing_bytes());
        action.signature = Some(hex::encode(signature.to_bytes()));
        let payload = serde_json::to_string(&action)?;

        let sent_at = Instant::now();
        let status = match http(&args.node, "/actions", Some(&payload), args.token.as_deref()) {
            Ok((status, _)) => status,
            Err(_) => 0, // connection-level failure, not an HTTP status
        };
        if status == 202 {
            nonces[sender_idx] = nonce + 1;
        }
        outcomes.push(Outcome { status, latency: sent_at.elapsed() });

        if let Some(interval) = interval {
            if let Some(remaining) = interval.checked_sub(sent_at.elapsed()) {
                std::thread::sleep(remaining);
            }
        }
    }
    let submit_wall = run_start.elapsed();

    let accepted = outcomes.iter().filter(|o| o.status == 202).count();
    let rate_limited = outcomes.iter().filter(|o| o.status == 429).count();
    let other_rejected = outcomes.len() - accepted - rate_limited;
    let mut latencies: Vec<Duration> = outcomes.iter().map(|o| o.latency).collect();
    latencies.sort();
    let p50 = latencies.get(latencies.len() / 2).copied().unwrap_or_default();
    let p99 = latencies.get(latencies.len() * 99 / 100).copied().unwrap_or_default();

    println!("--- submit phase ---");
    println!("sent: {}, accepted (202): {accepted}, rate-limited (429): {rate_limited}, other rejected: {other_rejected}", outcomes.len());
    println!("wall time: {:.2}s, actual throughput: {:.2}/s", submit_wall.as_secs_f64(), outcomes.len() as f64 / submit_wall.as_secs_f64());
    println!("submit latency: p50={p50:?} p99={p99:?}");

    // Confirmation phase: poll each sender's nonce until it matches what we
    // expect from accepted sends, or give up — this is the number that
    // actually matters (did the block-production pipeline keep up), not
    // just the 202 the RPC layer handed back on admission.
    // Polling this shares the same per-IP rate-limit budget as the submit
    // phase above, so a burst that already spent the budget would starve
    // fast polling here too (429, not "not yet included" — confirmed by a
    // manual re-check when this tool first hit exactly that during
    // development). Pace at 3s (>= BLOCK_INTERVAL, no point polling faster
    // than a block can land) and give it 90s so a burst gets a full 60s
    // window to recover before we give up.
    println!("--- confirming inclusion (up to 90s) ---");
    let confirm_start = Instant::now();
    let mut confirmed = vec![false; senders.len()];
    let mut rate_limited_last = vec![false; senders.len()];
    while confirm_start.elapsed() < Duration::from_secs(90) && confirmed.iter().any(|c| !c) {
        for (idx, addr) in addrs.iter().enumerate() {
            if confirmed[idx] {
                continue;
            }
            match get_nonce(&args.node, addr, args.token.as_deref()) {
                Ok(Some(chain_nonce)) => {
                    rate_limited_last[idx] = false;
                    if chain_nonce >= nonces[idx] {
                        confirmed[idx] = true;
                    }
                }
                Ok(None) => rate_limited_last[idx] = true,
                Err(_) => rate_limited_last[idx] = false,
            }
        }
        if confirmed.iter().any(|c| !c) {
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    for ((name, ok), rate_limited) in senders.iter().zip(&confirmed).zip(&rate_limited_last) {
        let status = match (ok, rate_limited) {
            (true, _) => "all accepted actions confirmed on-chain".to_string(),
            (false, true) => "unknown — still rate-limited (429) after 90s, not a confirmed inclusion failure".to_string(),
            (false, false) => "not yet included after 90s".to_string(),
        };
        println!("{name}: {status}");
    }
    println!("confirmation wall time: {:.2}s", confirm_start.elapsed().as_secs_f64());

    Ok(())
}
