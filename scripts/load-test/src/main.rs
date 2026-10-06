// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

// ponytail: devnet capacity benchmark. Raw std::net HTTP like scripts/send-tx;
// worker threads each own a disjoint slice of sender keys so nonces need no
// locking. The nodes' per-IP write rate limit must be raised for this to
// measure the chain rather than the limiter (ARXD_RPC_RATE_LIMIT_WRITES).
use anyhow::{Context, Result};
use arxd_runtime::ActionPayload;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xc_primitives::{Action, Address};

/// Ramps a signed-transfer load against one or more arxd RPC endpoints and
/// reports accepted vs committed throughput per step. Devnet only.
#[derive(Parser)]
struct Args {
    /// RPC endpoints (host:port), comma separated; workers round-robin them.
    #[arg(long, value_delimiter = ',', default_value = "127.0.0.1:30333")]
    nodes: Vec<String>,

    #[arg(long, default_value = "")]
    token: String,

    /// Print the funder's address and exit (to put it in a genesis spec).
    #[arg(long)]
    print_address: bool,

    /// File holding the funder's 64-hex ed25519 seed (a funded genesis account).
    #[arg(long)]
    funder_seed_file: String,

    #[arg(long, default_value_t = 100)]
    senders: usize,

    #[arg(long, default_value_t = 8)]
    workers: usize,

    /// Offered load per step, actions/sec.
    #[arg(long, value_delimiter = ',', default_value = "5,10,20,40,60,80")]
    steps: Vec<f64>,

    #[arg(long, default_value_t = 30)]
    step_secs: u64,
}

const FUND: u64 = 1_000_000_000_000;

fn http(node: &str, token: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let mut s = TcpStream::connect(node).with_context(|| format!("connect {node}"))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    let body = body.unwrap_or_default();
    let method = if body.is_empty() { "GET" } else { "POST" };
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {node}\r\nConnection: close\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut r = String::new();
    s.read_to_string(&mut r)?;
    let (head, rest) = r.split_once("\r\n\r\n").context("malformed response")?;
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .context("bad status line")?;
    Ok((code, rest.to_string()))
}

fn get_json(node: &str, token: &str, path: &str) -> Result<Value> {
    loop {
        let (code, body) = http(node, token, path, None)?;
        match code {
            200 => return Ok(serde_json::from_str(&body)?),
            404 => return Ok(Value::Null), // unfunded account
            429 => std::thread::sleep(Duration::from_secs(1)),
            _ => anyhow::bail!("GET {path} -> {code}: {body}"),
        }
    }
}

fn account(node: &str, token: &str, a: &Address) -> Result<(u64, u64)> {
    let v = get_json(node, token, &format!("/accounts/{a}"))?;
    Ok((
        v["balance"].as_u64().unwrap_or(0),
        v["nonce"].as_u64().unwrap_or(0),
    ))
}

/// `account` for many addresses at once; one serial round trip each is minutes
/// through a tunnel at a thousand senders.
fn accounts(node: &str, token: &str, addrs: &[&Address]) -> Result<Vec<(u64, u64)>> {
    let mut out = vec![(0, 0); addrs.len()];
    std::thread::scope(|sc| -> Result<()> {
        let hs: Vec<_> = out
            .chunks_mut(32)
            .zip(addrs.chunks(32))
            .map(|(o, a)| {
                sc.spawn(move || -> Result<()> {
                    for (slot, addr) in o.iter_mut().zip(a) {
                        *slot = account(node, token, addr)?;
                    }
                    Ok(())
                })
            })
            .collect();
        hs.into_iter().try_for_each(|h| h.join().unwrap())
    })?;
    Ok(out)
}

struct Key {
    sk: SigningKey,
    addr: Address,
}

fn key(seed: [u8; 32]) -> Key {
    let sk = SigningKey::from_bytes(&seed);
    let addr = Address::from_pubkey_bytes(sk.verifying_key().as_bytes()).unwrap();
    Key { sk, addr }
}

fn transfer(genesis: &[u8; 32], k: &Key, nonce: u64, to: &Address, amount: u64) -> String {
    let mut a = Action {
        sender: k.addr.clone(),
        nonce,
        signature: None,
        payload: ActionPayload::Transfer {
            to: to.clone(),
            amount: amount as _,
        },
    };
    a.signature = Some(hex::encode(k.sk.sign(&a.signing_bytes(genesis)).to_bytes()));
    serde_json::to_string(&a).unwrap()
}

#[derive(Default, Clone)]
struct Tally {
    ok: u64,
    limited: u64,
    full: u64,
    other: u64,
    lat: Vec<Duration>,
}

fn pct(v: &[Duration], p: usize) -> Duration {
    v.get((v.len() * p / 100).min(v.len().saturating_sub(1)))
        .copied()
        .unwrap_or_default()
}

/// Tip height plus, for a height range, (actions, weight_used) per block and
/// first/last timestamps — the committed side of the measurement.
fn tip(node: &str, token: &str) -> Result<u64> {
    get_json(node, token, "/status")?["tip_height"]
        .as_u64()
        .context("tip_height")
}

fn chain_stats(node: &str, token: &str, from: u64, to: u64) -> Result<(u64, u64, u64, u64)> {
    let (mut acts, mut weight, mut t0, mut t1) = (0, 0, 0, 0);
    let mut h = from;
    while h <= to {
        let end = (h + 19).min(to);
        let blocks = get_json(node, token, &format!("/blocks?from={h}&to={end}"))?;
        for b in blocks.as_array().context("blocks array")? {
            acts += b["actions"].as_array().map_or(0, |a| a.len() as u64);
            weight += b["weight_used"].as_u64().unwrap_or(0);
            let ts = b["timestamp"].as_u64().unwrap_or(0);
            if t0 == 0 {
                t0 = ts;
            }
            t1 = ts;
        }
        h = end + 1;
    }
    Ok((acts, weight, t0, t1))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (token, node0) = (args.token.as_str(), args.nodes[0].as_str());

    let seed: [u8; 32] = hex::decode(std::fs::read_to_string(&args.funder_seed_file)?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("funder seed must be 32 bytes"))?;
    let funder = key(seed);
    if args.print_address {
        println!("{}", funder.addr);
        return Ok(());
    }
    let genesis: [u8; 32] = hex::decode(
        get_json(node0, token, "/genesis-hash")?["genesis_hash"]
            .as_str()
            .context("genesis-hash response missing genesis_hash")?
            .trim_start_matches("0x"),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("genesis_hash is not 32 bytes"))?;
    let senders: Vec<Key> = (0..args.senders)
        .map(|i| {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(b"arxbench");
            s[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            key(s)
        })
        .collect();

    // Fund phase: skip senders already funded (re-runs), 60 per wave so the
    // funder stays under the per-sender mempool cap.
    let bal = accounts(
        node0,
        token,
        &senders.iter().map(|k| &k.addr).collect::<Vec<_>>(),
    )?;
    let todo: Vec<&Key> = senders
        .iter()
        .zip(&bal)
        .filter(|(_, b)| b.0 < FUND / 2)
        .map(|(k, _)| k)
        .collect();
    println!("funding {} of {} senders", todo.len(), senders.len());
    for wave in todo.chunks(60) {
        let (_, mut nonce) = account(node0, token, &funder.addr)?;
        for k in wave {
            let (code, body) = http(
                node0,
                token,
                "/actions",
                Some(&transfer(&genesis, &funder, nonce, &k.addr, FUND)),
            )?;
            anyhow::ensure!(code == 202, "fund rejected {code}: {body}");
            nonce += 1;
        }
        let t = Instant::now();
        while account(node0, token, &funder.addr)?.1 < nonce {
            anyhow::ensure!(t.elapsed() < Duration::from_secs(120), "fund wave stuck");
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    // Hand each worker a disjoint slice with chain-synced nonces.
    let nonces: Vec<u64> = accounts(
        node0,
        token,
        &senders.iter().map(|k| &k.addr).collect::<Vec<_>>(),
    )?
    .into_iter()
    .map(|a| a.1)
    .collect();
    let senders = Arc::new(senders);
    let nonces = Arc::new(Mutex::new(nonces));
    let addrs: Arc<Vec<Address>> = Arc::new(senders.iter().map(|k| k.addr.clone()).collect());

    println!("step_tps offered accepted rl429 full503 other p50_ms p99_ms | committed_tps acts/block weight% drain_left");
    for &rate in &args.steps {
        let h0 = tip(node0, token)?;
        let workers = args.workers;
        let per_worker = rate / workers as f64;
        let handles: Vec<_> = (0..args.workers)
            .map(|w| {
                let (senders, nonces, addrs) = (senders.clone(), nonces.clone(), addrs.clone());
                let (node, token) = (args.nodes[w % args.nodes.len()].clone(), args.token.clone());
                let genesis = genesis;
                let dur = Duration::from_secs(args.step_secs);
                std::thread::spawn(move || {
                    let mine: Vec<usize> = (w..senders.len()).step_by(workers).collect();
                    let mut t = Tally::default();
                    let mut local: Vec<u64> = {
                        let n = nonces.lock().unwrap();
                        mine.iter().map(|&i| n[i]).collect()
                    };
                    let gap = Duration::from_secs_f64(1.0 / per_worker);
                    let begin = Instant::now();
                    let mut i = 0u64;
                    while begin.elapsed() < dur {
                        let slot = (i as usize) % mine.len();
                        let idx = mine[slot];
                        let to = &addrs[(idx + 1) % addrs.len()];
                        let body = transfer(&genesis, &senders[idx], local[slot], to, 1);
                        let sent = Instant::now();
                        match http(&node, &token, "/actions", Some(&body)) {
                            Ok((202, _)) => {
                                t.ok += 1;
                                local[slot] += 1;
                            }
                            Ok((429, _)) => t.limited += 1,
                            Ok((503, _)) => t.full += 1,
                            _ => t.other += 1,
                        }
                        t.lat.push(sent.elapsed());
                        i += 1;
                        if let Some(wait) = (gap * i as u32).checked_sub(begin.elapsed()) {
                            std::thread::sleep(wait);
                        }
                    }
                    let mut n = nonces.lock().unwrap();
                    for (slot, &idx) in mine.iter().enumerate() {
                        n[idx] = local[slot];
                    }
                    t
                })
            })
            .collect();
        let mut total = Tally::default();
        for h in handles {
            let t = h.join().unwrap();
            total.ok += t.ok;
            total.limited += t.limited;
            total.full += t.full;
            total.other += t.other;
            total.lat.extend(t.lat);
        }
        let offered = total.ok + total.limited + total.full + total.other;
        total.lat.sort();

        // Committed throughput is what landed while load was on; the drain
        // after it only sizes the leftover backlog.
        let h_end = tip(node0, token)?;
        let (acts, weight, ..) = chain_stats(node0, token, h0 + 1, h_end)?;
        std::thread::sleep(Duration::from_secs(8));
        let (all, ..) = chain_stats(node0, token, h0 + 1, tip(node0, token)?)?;
        let blocks = (h_end - h0).max(1) as f64;
        println!(
            "{:>7.0} {:>7} {:>8} {:>5} {:>7} {:>5} {:>6.0} {:>6.0} | {:>13.1} {:>10.1} {:>7.1} {:>10}",
            rate,
            offered,
            total.ok,
            total.limited,
            total.full,
            total.other,
            pct(&total.lat, 50).as_secs_f64() * 1e3,
            pct(&total.lat, 99).as_secs_f64() * 1e3,
            acts as f64 / args.step_secs as f64,
            acts as f64 / blocks,
            weight as f64 / blocks / 10_000.0,
            total.ok.saturating_sub(all),
        );
    }
    Ok(())
}
