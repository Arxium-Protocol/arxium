// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

// ponytail: raw std::net HTTP client, same as `scripts/send-tx` — this CLI
// command can't depend on that crate (it already depends on `node`), and
// pulling in a full HTTP client for one signed POST/GET-poll loop isn't
// worth it.
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use xc_primitives::Address;

use runtime::{ActionPayload, ChainAction};
use crate::validator;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
// Mirrors the RPC server's own `PAIRING_TTL` (`core/rpc`) — no point
// polling past the point the server has already dropped the session.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(300);

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

fn print_qr(contents: &str) -> Result<()> {
    let code = qrcode::QrCode::new(contents).context("failed to render pairing QR code")?;
    let image = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .build();
    println!("{image}");
    Ok(())
}

#[derive(Serialize)]
struct QrPayload<'a> {
    validator: &'a Address,
    nonce: &'a str,
}

#[derive(Deserialize)]
struct StartPairingResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct PollPairingResponse {
    operator: Address,
}

/// Polls `GET /pairing/{nonce}` until the app has submitted an operator
/// address (`200`), the session expires server-side (`404`), or
/// `PAIRING_TIMEOUT` passes locally.
fn wait_for_operator(node: &str, token: Option<&str>, nonce: &str) -> Result<Address> {
    let deadline = Instant::now() + PAIRING_TIMEOUT;
    loop {
        let (status, body) = http("GET", node, &format!("/pairing/{nonce}"), None, token)?;
        match status {
            200 => {
                let response: PollPairingResponse =
                    serde_json::from_str(&body).context("malformed pairing response")?;
                return Ok(response.operator);
            }
            202 => {}
            404 => bail!("pairing session expired before the app confirmed it — run `arxd pair` again"),
            other => bail!("GET /pairing/{nonce} -> {other}: {body}"),
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for the app to confirm pairing");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Fetches this account's current nonce. A freshly generated validator key
/// that has never received funds or submitted anything has no account
/// entry yet (`404`) — that's the expected first-run state for this
/// command, not an error, and the chain treats such a sender's nonce as 0
/// (see `xc_mempool::validate_action`), so this does too.
fn fetch_nonce(node: &str, token: Option<&str>, sender: &Address) -> Result<u64> {
    let (status, body) = http("GET", node, &format!("/accounts/{sender}"), None, token)?;
    match status {
        200 => serde_json::from_str::<serde_json::Value>(&body)?["nonce"]
            .as_u64()
            .context("account response missing nonce"),
        404 => Ok(0),
        other => bail!("GET /accounts/{sender} -> {other}: {body}"),
    }
}

fn sign_and_submit(
    node: &str,
    token: Option<&str>,
    key: &SigningKey,
    sender: Address,
    payload: ActionPayload,
) -> Result<()> {
    let nonce = fetch_nonce(node, token, &sender)?;
    let mut action = ChainAction {
        sender,
        nonce,
        signature: None,
        payload,
    };
    let signature = key.sign(&action.signing_bytes());
    action.signature = Some(hex::encode(signature.to_bytes()));

    let body = serde_json::to_string(&action)?;
    let (status, body) = http("POST", node, "/actions", Some(&body), token)?;
    if status != 202 {
        bail!("node rejected the action: {status} {body}");
    }
    Ok(())
}

/// Implements `arxd pair` / `arxd pair --revoke` — see `Command::Pair`'s doc
/// comment for the full flow. The validator's signing key is loaded
/// in-process (`validator::load_or_generate_key`) and never serialized or
/// transmitted anywhere; only the resulting signed `AuthorizeOperator` /
/// `RevokeOperator` action is sent over the wire.
pub fn run(base_path: &std::path::Path, node: &str, token: Option<&str>, revoke: bool) -> Result<()> {
    // The pairing session this command creates lives only in this node
    // process's memory (see core/rpc's PairingStore) — printed up front so
    // a mismatch against whatever node the app's backend actually talks to
    // (NODE_RPC_URL) is obvious immediately, not after a confusing "expired"
    // report from the app minutes later.
    println!("Connecting to node at {node}{}", if token.is_some() { " (with token)" } else { "" });
    let key = validator::load_or_generate_key(base_path)?;
    let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes())
        .context("validator key produced an invalid address")?;

    if revoke {
        sign_and_submit(node, token, &key, sender, ActionPayload::RevokeOperator)?;
        println!("operator revoked");
        return Ok(());
    }

    let (status, body) = http(
        "POST",
        node,
        "/pairing",
        Some(&serde_json::json!({ "validator": &sender }).to_string()),
        token,
    )?;
    if status != 200 {
        bail!("POST /pairing -> {status}: {body}");
    }
    let session: StartPairingResponse =
        serde_json::from_str(&body).context("malformed /pairing response")?;

    println!("Scan this in the app's \"Add Validator\" screen (expires in 5 minutes):");
    print_qr(&serde_json::to_string(&QrPayload {
        validator: &sender,
        nonce: &session.nonce,
    })?)?;
    println!("Waiting for the app to confirm...");

    let operator = wait_for_operator(node, token, &session.nonce)?;
    println!("App confirmed — authorizing {operator} as operator for {sender}");

    sign_and_submit(
        node,
        token,
        &key,
        sender,
        ActionPayload::AuthorizeOperator { operator },
    )?;
    println!("pairing complete");
    Ok(())
}
