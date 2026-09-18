// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Query, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use xc_mempool::{AdmissionError, Mempool, MempoolError, PayloadPrecheck, validate_action};
use xc_primitives::{
    Action, Address, Asset, AssetRef, Block, Hash32, Limits, QUORUM_POWER, TOTAL_VOTING_POWER,
    signed_power,
};
use xc_storage::{ArxiumDb, StorageError};

mod error;
use error::ApiError;

mod pairing;
use pairing::*;
mod admin;
use admin::*;
mod proofs;
use proofs::*;
mod accounts;
use accounts::*;
mod assets;
use assets::*;
mod validators;
use validators::*;
mod blocks;
use blocks::*;

/// `Address::parse`, mapped to the 400 every handler already gave it.
fn parse_address(s: &str) -> Result<Address, ApiError> {
    Address::parse(s).map_err(|err| ApiError::BadRequest(err.to_string()))
}

/// Resolves a `?height=` query param against the tip, rejecting one above it
/// — answering with the tip's set would look like data rather than the
/// caller mistake it is. `None` means "as of the tip".
fn resolve_height(requested: Option<u64>, tip_height: u64) -> Result<u64, ApiError> {
    match requested {
        Some(h) if h > tip_height => Err(ApiError::BadRequest(format!(
            "height {h} is above the chain tip {tip_height}"
        ))),
        Some(h) => Ok(h),
        None => Ok(tip_height),
    }
}

/// Bound every chain's payload type must satisfy to be served over this RPC:
/// JSON (de)serializable for the wire, `Clone` because `AppState` is cloned
/// per request, `Send + Sync + 'static` to live inside the shared axum state.
pub trait Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> Payload for P {}

// Every limit below now comes from `xc_primitives::Limits` (operator-set,
// defaulting to exactly these devnet values):
//
// - the cap on a single JSON action body,
// - the rate-limit window and the per-IP write budget inside it. Writes
//   (state-mutating: POST /actions, POST /pairing) keep the tight budget —
//   this is the one that actually bounds spam/DoS risk against the mempool
//   and chain state,
// - the per-IP read budget. Reads (GET /accounts/*, /blocks/*, ...) are
//   cheap lookups against already-committed state, not a mempool/consensus
//   risk, so they get a much higher ceiling. Load-testing this RPC
//   (scripts/load-test) surfaced the bug a single shared budget causes: a
//   client's own status-check polling right after a submission burst would
//   get starved by its own writes, making confirmed-on-chain actions look
//   "still pending" indefinitely.

// Sweep stale per-IP entries once the map crosses this size, bounding worst-
// case memory instead of growing forever for a public/long-lived instance.
// Not operator-tunable: it bounds this map's memory, it is not a policy knob.
const RATE_LIMIT_SWEEP_THRESHOLD: usize = 10_000;

// One bucket for every request that matched no route, so 404 traffic cannot
// mint labels either.
const UNMATCHED_PATH: &str = "<unmatched>";

#[derive(Clone)]
struct AppState<P: Payload> {
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    rpc_token: Option<Arc<String>>,
    admin_token: Option<Arc<String>>,
    rate_limiter: Arc<RateLimiter>,
    // Number of trusted proxies in front of this RPC — see `client_ip`.
    trusted_proxy_hops: usize,
    // How far ahead of a sender's on-chain nonce a submitted action may be —
    // see `xc_mempool::validate_action`.
    max_nonce_gap: u64,
    // Broadcasts freshly admitted actions out to peers over gossip. `None`
    // in tests / any caller that doesn't wire up `network`.
    gossip_tx: Option<tokio::sync::mpsc::UnboundedSender<Action<P>>>,
    metrics_handle: PrometheusHandle,
    // Chain-specific admission rules (e.g. arxd/node's validator
    // authorization/min-stake checks) layered on top of the payload-agnostic
    // `validate_action`. `None` for chains with no such rules.
    payload_precheck: Option<PayloadPrecheck<P>>,
    pairing: Arc<PairingStore>,
    // Chain-specific minimum validator stake (e.g. arxd/node's
    // `MIN_VALIDATOR_STAKE`), so a client never has to hardcode it. `None`
    // for chains with no such floor.
    min_stake: Option<u128>,
    // Chain-specific flat per-action fee (e.g. arxd/node's `ACTION_FEE`), so
    // a client can show it before submitting. `None` for chains with no fee.
    action_fee: Option<u128>,
    weight_fee: u128,
    // Where `xc_evidence` writes fault artifacts (see `write_equivocation_artifact`
    // / `write_disagreement_artifact`). `GET /evidence*` just lists/serves this
    // directory's contents — no separate storage of its own.
    evidence_dir: PathBuf,
}

/// Fixed window, per-IP, in this process's memory only. Deliberately a
/// backstop rather than the deployment's rate limit: behind more than one
/// RPC instance each keeps its own counters, so N instances multiply every
/// budget by N. The public deployment limits at the edge instead
/// (`limit_req` in nginx-gateway.conf), which is also the only layer that
/// can shed load before it reaches this process at all. Keep both: the edge
/// protects the fleet, this protects a node someone points a client at
/// directly.
struct RateLimiter {
    // Keyed by (ip, is_write) so a client's write budget and read budget
    // are tracked — and exhausted — independently. Same map/sweep shape as
    // the single-budget version, just keyed one level deeper.
    hits: Mutex<HashMap<(IpAddr, bool), (Instant, u32)>>,
    window: Duration,
    max_writes: u32,
    max_reads: u32,
}

impl RateLimiter {
    fn new(limits: &Limits) -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            window: Duration::from_secs(limits.rpc_rate_limit_window_secs),
            max_writes: limits.rpc_rate_limit_writes,
            max_reads: limits.rpc_rate_limit_reads,
        }
    }

    fn allow(&self, ip: IpAddr, is_write: bool) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Sweep stale entries once the map gets large rather than every call —
        // bounds worst-case memory without paying a scan on every request.
        if hits.len() > RATE_LIMIT_SWEEP_THRESHOLD {
            hits.retain(|_, (seen, _)| now.duration_since(*seen) <= self.window);
        }

        let max = if is_write {
            self.max_writes
        } else {
            self.max_reads
        };
        let entry = hits.entry((ip, is_write)).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }
}

/// The client IP to key rate limiting on. Behind a reverse proxy the socket
/// address is the proxy's, so every real client would collapse into one IP
/// and share a single budget — but a client-supplied `X-Forwarded-For` is
/// forgeable, so the header is only usable if we know exactly how many
/// trusted hops appended to it. That is what `trusted_hops`
/// (`--rpc-trusted-proxy-hops`) states, and it defaults to 0: trust nothing,
/// key on the socket address.
///
/// Entries are counted from the *right*, never the left. Each trusted proxy
/// appends the address it observed (nginx's `$proxy_add_x_forwarded_for`),
/// so the last entry was appended by the hop nearest this node and the
/// client's own address was appended by the outermost trusted proxy —
/// exactly `trusted_hops` entries from the end. Everything further left was
/// supplied by the client and is ignored. The shipped deployment
/// (`docker-compose.prod.yml`) is two appending hops, nginx-proxy →
/// gateway → arxd, so it runs with `--rpc-trusted-proxy-hops 2`.
///
/// A header with fewer entries than the configured hop count means the
/// request did not arrive through the configured chain, so it falls back to
/// the socket address rather than picking whatever is there.
fn client_ip(req: &Request, addr: SocketAddr, trusted_hops: usize) -> IpAddr {
    if trusted_hops == 0 {
        return addr.ip();
    }
    let Some(forwarded) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return addr.ip();
    };
    let entries: Vec<&str> = forwarded.split(',').map(str::trim).collect();
    entries
        .len()
        .checked_sub(trusted_hops)
        .and_then(|i| entries[i].parse::<IpAddr>().ok())
        .unwrap_or(addr.ip())
}

async fn guard<P: Payload>(
    State(state): State<AppState<P>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // The matched *route template* (`/accounts/{address}`), never the request
    // path: addresses, hashes, signatures and heights all appear in path
    // segments, and `metrics-exporter-prometheus` never evicts a label set —
    // so keying on the real path grows the registry without bound on ordinary
    // explorer traffic, and lets anyone drive that growth deliberately (this
    // runs on 404s and on rate-limited requests too). Captured before `req`
    // moves into `next.run`. Requests that matched no route have no template
    // and share one bucket.
    let path = req.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_PATH.to_string(),
        |matched| matched.as_str().to_string(),
    );
    let is_write = req.method() != Method::GET;

    if let Some(token) = &state.rpc_token {
        let expected = format!("Bearer {token}");
        let authorized = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.len() == expected.len() && value.as_bytes().ct_eq(expected.as_bytes()).into()
            });
        if !authorized {
            record_request(&path, StatusCode::UNAUTHORIZED);
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    if !state
        .rate_limiter
        .allow(client_ip(&req, addr, state.trusted_proxy_hops), is_write)
    {
        record_request(&path, StatusCode::TOO_MANY_REQUESTS);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let response = next.run(req).await;
    record_request(&path, response.status());
    response
}

fn record_request(path: &str, status: StatusCode) {
    metrics::counter!(
        "arxium_rpc_requests_total",
        "path" => path.to_string(),
        "status" => status.as_u16().to_string(),
    )
    .increment(1);
}

/// Renders the current metrics snapshot in Prometheus text format. Outside
/// the bearer-token guard (metrics aren't secret and this endpoint isn't
/// meant to be internet-facing — see `docker-compose.prod.yml`, whose gateway
/// returns 404 for it rather than proxying it).
async fn get_metrics<P: Payload>(State(state): State<AppState<P>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics_handle.render(),
    )
        .into_response()
}

/// Runs the RPC server on its own tokio runtime, on a dedicated thread, so
/// the rest of the node (bootstrap, block production loop) stays plain sync.
/// Generic over the chain's own payload type `P` — this crate never knows
/// what an action's payload means, only how to move `Action<P>` in and out
/// of JSON and the mempool.
///
/// Serves `POST /actions` (submit a JSON-encoded `Action<P>`, queued into
/// `mempool` for the next block), `GET /accounts/{address}` (current
/// balance/nonce, needed to sign the next action),
/// `GET /actions/{signature}` (pending/confirmed status of a submitted
/// action), `GET /status` (chain name, tip height/hash), and `GET /metrics`
/// (Prometheus text format, ungated — see `get_metrics`). If `rpc_token`
/// is set, every request must carry a matching
/// `Authorization: Bearer` header. Blocks the caller until the listener is
/// bound (or fails to bind), same as a sync server would, so startup
/// failures surface immediately instead of on first request.
/// `spawn_http_ingest`'s arguments as named fields — `min_stake` and
/// `action_fee` are both `Option<u128>` and used to sit next to each other in
/// a twelve-parameter list, where transposing them would have compiled and
/// quietly repriced every action.
pub struct IngestConfig<P: Payload> {
    pub mempool: Arc<Mutex<Mempool<P>>>,
    pub db: ArxiumDb,
    pub bind_addr: String,
    pub port: u16,
    pub rpc_token: Option<String>,
    /// See `NodeConfig::admin_token`. `None` leaves `/admin/*` unmounted.
    pub admin_token: Option<String>,
    pub gossip_tx: Option<tokio::sync::mpsc::UnboundedSender<Action<P>>>,
    pub metrics_handle: PrometheusHandle,
    pub payload_precheck: Option<PayloadPrecheck<P>>,
    pub min_stake: Option<u128>,
    pub action_fee: Option<u128>,
    /// Fee per weight unit on top of `action_fee` — 0 for an unmetered chain.
    pub weight_fee: u128,
    pub evidence_dir: PathBuf,
    pub limits: Limits,
}

pub fn spawn_http_ingest<P: Payload>(config: IngestConfig<P>) -> Result<()> {
    let IngestConfig {
        mempool,
        db,
        bind_addr,
        port,
        rpc_token,
        admin_token,
        gossip_tx,
        metrics_handle,
        payload_precheck,
        min_stake,
        action_fee,
        weight_fee,
        evidence_dir,
        limits,
    } = config;
    if rpc_token.is_none()
        && bind_addr
            .parse::<IpAddr>()
            .is_ok_and(|ip| !ip.is_loopback())
    {
        warn!(
            "RPC bound to {bind_addr} with no --rpc-token: anyone who can reach it can submit actions"
        );
    }

    let (ready_tx, ready_rx) = mpsc::channel::<std::io::Result<()>>();
    let state = AppState {
        mempool,
        db,
        rpc_token: rpc_token.map(Arc::new),
        admin_token: admin_token.map(Arc::new),
        rate_limiter: Arc::new(RateLimiter::new(&limits)),
        trusted_proxy_hops: limits.rpc_trusted_proxy_hops,
        max_nonce_gap: limits.mempool_max_nonce_gap,
        gossip_tx,
        metrics_handle,
        payload_precheck,
        pairing: Arc::new(PairingStore::new()),
        min_stake,
        action_fee,
        weight_fee,
        evidence_dir,
    };

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };

        runtime.block_on(async move {
            // /metrics is deliberately outside the guarded router below — a
            // scrape endpoint shouldn't need the RPC bearer token, and it's
            // never routed through the public TLS proxy in production (the
            // gateway in docker-compose.prod.yml returns 404 for it) since
            // it's only meant for an internal scraper on the same docker
            // network.
            let guarded = Router::new()
                .route("/actions", post(submit_action::<P>))
                .route("/accounts/{address}", get(get_account::<P>))
                .route("/accounts/{address}/proof", get(get_account_proof::<P>))
                .route("/accounts/{address}/stake", get(get_account_stake::<P>))
                .route("/accounts/{address}/stakes", get(get_account_stakes::<P>))
                .route("/accounts/{address}/bls-key", get(get_account_bls_key::<P>))
                .route("/accounts/{address}/assets", get(get_account_assets::<P>))
                .route(
                    "/accounts/{address}/assets/{asset_ref}",
                    get(get_account_asset_balance::<P>),
                )
                .route(
                    "/accounts/{address}/assets/{asset_ref}/proof",
                    get(get_account_asset_balance_proof::<P>),
                )
                .route("/assets", get(get_assets::<P>))
                .route("/assets/alias/{issuer}/{asset_id}", get(get_asset_alias::<P>))
                .route("/assets/{asset_ref}", get(get_asset::<P>))
                .route("/assets/{asset_ref}/holders", get(get_asset_holders::<P>))
                .route("/attestors", get(get_attestors::<P>))
                .route("/attestors/{address}", get(get_attestor::<P>))
                .route("/validators", get(get_validators::<P>))
                .route("/validators/{address}", get(get_validator::<P>))
                .route("/validators/{address}/proof", get(get_validator_proof::<P>))
                .route("/validators/power", get(get_validator_power::<P>))
                .route("/finality", get(get_finality::<P>))
                .route("/genesis-hash", get(get_genesis_hash::<P>))
                .route("/operators/{address}/validators", get(get_operator_validators::<P>))
                .route(
                    "/stake/{master}/{validator}",
                    get(get_delegated_stake::<P>),
                )
                .route("/actions/{signature}", get(get_action_status::<P>))
                .route("/blocks", get(get_blocks::<P>))
                .route("/blocks/{height}", get(get_block_by_height::<P>))
                .route("/blocks/by-hash/{hash}", get(get_block_by_hash::<P>))
                .route("/evidence", get(get_evidence_list::<P>))
                .route("/evidence/{id}", get(get_evidence_by_id::<P>))
                .route("/search", get(search::<P>))
                .route("/status", get(get_status::<P>))
                .route("/min-stake", get(get_min_stake::<P>))
                .route("/action-fee", get(get_action_fee::<P>))
                .route("/pairing", post(start_pairing::<P>))
                .route(
                    "/pairing/{nonce}",
                    post(submit_pairing::<P>).get(poll_pairing::<P>),
                )
                // After every route so it covers `/pairing*` too — a `.layer`
                // only wraps the routes added before it.
                .layer(DefaultBodyLimit::max(limits.rpc_max_body_bytes))
                .with_state(state.clone())
                .layer(middleware::from_fn_with_state(state.clone(), guard::<P>));

            // Operator-only routes, gated on their own token and mounted only
            // when one is configured. Not in `guarded`: that shares
            // `rpc_token` with every client that submits actions, and a
            // route that writes a full DB copy to the node's disk shouldn't
            // be reachable with it. The public gateway 404s `/admin/*`
            // (`nginx-gateway.conf`), same as `/metrics`.
            let admin = if state.admin_token.is_some() {
                Router::new()
                    .route("/admin/checkpoint", post(admin_checkpoint::<P>))
                    .with_state(state.clone())
                    .layer(middleware::from_fn_with_state(state.clone(), admin_guard::<P>))
            } else {
                Router::new()
            };

            let app = Router::new()
                .route("/metrics", get(get_metrics::<P>))
                .with_state(state)
                .merge(guarded)
                .merge(admin)
                // All reads are public and writes are gated by the bearer
                // token above (never a cookie), so there's no session to
                // leak cross-origin — open to any origin, same as any public
                // block explorer's backend, rather than hardcoding one.
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                );

            let listener = match tokio::net::TcpListener::bind((bind_addr.as_str(), port)).await {
                Ok(listener) => listener,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            info!(
                "RPC listening on {bind_addr}:{port} (POST /actions, GET /accounts/:address, GET /actions/:signature, GET /status)"
            );
            let _ = ready_tx.send(Ok(()));

            let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
            if let Err(err) = axum::serve(listener, make_service).await {
                warn!("RPC server exited: {err}");
            }
        });
    });

    ready_rx
        .recv()
        .context("RPC server thread died before starting")?
        .with_context(|| format!("failed to bind RPC listener on port {port}"))
}

/// Runs the action through `xc_mempool::validate_action` (signature +
/// stale-nonce check — see its doc comment), then the chain's optional
/// `payload_precheck` (e.g. validator authorization/min-stake), before it
/// ever touches the mempool — same as gossip-received actions do in
/// `network`. A rejection at either stage is a real 4xx with the actual
/// reason, not a silent drop later at block production.
async fn submit_action<P: Payload>(
    State(state): State<AppState<P>>,
    body: Result<Json<Action<P>>, JsonRejection>,
) -> Response {
    let action = match body {
        Ok(Json(action)) => action,
        Err(err) => {
            warn!("rejected unparsable RPC action: {err}");
            return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
        }
    };
    let sender = action.sender.clone();

    match validate_action(&state.db, &action, state.max_nonce_gap) {
        Ok(()) => {}
        Err(err @ AdmissionError::Storage(_)) => {
            warn!("failed to validate action from {sender}: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(err) => {
            warn!("rejected action from {sender}: {err}");
            return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
        }
    }

    if let Some(precheck) = &state.payload_precheck
        && let Err(err) = precheck(&action, &state.db)
    {
        warn!("rejected action from {sender}: {err}");
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    let gossip_action = state.gossip_tx.is_some().then(|| action.clone());
    match state
        .mempool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(action)
    {
        Ok(()) => {
            info!("queued action from {sender} via RPC");
            if let (Some(tx), Some(action)) = (&state.gossip_tx, gossip_action) {
                let _ = tx.send(action);
            }
            StatusCode::ACCEPTED.into_response()
        }
        // Both are "come back later": the global queue is full, or this
        // sender is holding its share of it.
        Err(err @ (MempoolError::Full | MempoolError::SenderQueueFull { .. })) => {
            warn!("rejected action from {sender}: {err}");
            (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response()
        }
        Err(err @ MempoolError::Duplicate { .. }) => {
            warn!("rejected action from {sender}: {err}");
            (StatusCode::CONFLICT, err.to_string()).into_response()
        }
        Err(err @ MempoolError::TooLarge { .. }) => {
            metrics::counter!("arxium_mempool_rejected_oversized_total").increment(1);
            warn!("rejected action from {sender}: {err}");
            (StatusCode::PAYLOAD_TOO_LARGE, err.to_string()).into_response()
        }
    }
}

/// Chain-wide health: name, tip height/hash. No per-account or per-action
/// state, so unlike other routes it can't 404 — an initialized node always
/// has at least the genesis block.
async fn get_status<P: Payload>(State(state): State<AppState<P>>) -> Result<Response, ApiError> {
    let chain_name = state
        .db
        .get_chain_name()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let tip_height = state
        .db
        .get_tip_height()?
        .ok_or(ApiError::ServiceUnavailable)?;
    let tip_hash = state
        .db
        .get_block::<P>(tip_height)?
        .ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!(
                "tip height {tip_height} recorded but block is missing"
            ))
        })?
        .hash();
    let genesis_hash = state
        .db
        .genesis_hash()?
        .ok_or(ApiError::ServiceUnavailable)?;

    // Additive: existing consumers keep reading the three fields they know.
    // A wallet showing confirmations needs finality from the same call it
    // already makes, not a second round trip.
    let finalized_height = state.db.get_finalized_height().unwrap_or_else(|err| {
        warn!("failed to read finalized height for /status: {err}");
        None
    });

    // The one field a wallet asking "is my transfer settled" can actually act
    // on: `finalized_height` is the highest *certified* height and may sit
    // above an uncertified gap, while this is the floor below which nothing
    // will ever be reverted. See `ArxiumDb::get_final_watermark`.
    let final_watermark = state.db.get_final_watermark().unwrap_or_else(|err| {
        warn!("failed to read final watermark for /status: {err}");
        0
    });

    Ok(Json(serde_json::json!({
        "chain_name": chain_name,
        // This crate's version — bumped whenever the JSON shape of a block
        // changes, so an HTTP reader (Retracer) can refuse a node whose
        // blocks it would misread instead of finding out from the data.
        "version": env!("CARGO_PKG_VERSION"),
        "genesis_hash": genesis_hash,
        "tip_height": tip_height,
        "tip_hash": tip_hash,
        "finalized_height": finalized_height,
        "final_watermark": final_watermark,
    }))
    .into_response())
}

/// Chain-specific minimum validator stake (e.g. arxd/node's
/// `MIN_VALIDATOR_STAKE`), so a client (app, `arxd pair`) never has to
/// hardcode it. `404` for a chain with no such floor.
async fn get_min_stake<P: Payload>(State(state): State<AppState<P>>) -> Response {
    match state.min_stake {
        Some(min_stake) => Json(serde_json::json!({ "min_stake": min_stake })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Chain-specific flat per-action fee (e.g. arxd/node's `ACTION_FEE`), so a
/// client can show it before submitting. `404` for a chain with no fee.
/// `action_fee` is the base; a client estimates a real fee as
/// `action_fee + weight × weight_fee` (see `arxd_runtime::metering`), and
/// `max_block_weight` is the cap any single action must fit under.
async fn get_action_fee<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Response, ApiError> {
    let action_fee = state.action_fee.ok_or(ApiError::NotFound)?;
    let max_block_weight = state.db.chain_params()?.max_block_weight;
    Ok(Json(serde_json::json!({
        "action_fee": action_fee,
        "weight_fee": state.weight_fee,
        "max_block_weight": max_block_weight,
    }))
    .into_response())
}

/// The genesis state root bound into every BLS finality signature. External
/// verifiers must pin this value rather than infer network identity from a
/// mutable chain-name label.
async fn get_genesis_hash<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Response, ApiError> {
    let genesis_hash = state
        .db
        .genesis_hash()?
        .ok_or(ApiError::ServiceUnavailable)?;
    Ok(Json(serde_json::json!({ "genesis_hash": genesis_hash })).into_response())
}

#[cfg(test)]
mod rate_limiter_tests {
    use super::{IpAddr, Limits, RateLimiter};

    #[test]
    fn write_budget_exhausting_does_not_affect_reads() {
        let limits = Limits::default();
        let limiter = RateLimiter::new(&limits);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..limits.rpc_rate_limit_writes {
            assert!(limiter.allow(ip, true));
        }
        assert!(!limiter.allow(ip, true), "write budget should be exhausted");

        // Reads for the same IP draw from a separate, larger budget — this
        // is the fix for a client's own status-check polling getting
        // starved by a submission burst it just made.
        assert!(
            limiter.allow(ip, false),
            "read budget must be independent of the write budget"
        );
    }

    #[test]
    fn read_budget_is_higher_than_write_budget() {
        let limits = Limits::default();
        let limiter = RateLimiter::new(&limits);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..limits.rpc_rate_limit_reads {
            assert!(limiter.allow(ip, false));
        }
        assert!(!limiter.allow(ip, false));
        assert!(limits.rpc_rate_limit_reads > limits.rpc_rate_limit_writes);
    }

    /// An operator lowering a budget must actually lower it — the flag is
    /// pointless if the limiter still reads the compiled-in default.
    #[test]
    fn a_configured_budget_replaces_the_default() {
        let limits = Limits {
            rpc_rate_limit_writes: 2,
            ..Limits::default()
        };
        let limiter = RateLimiter::new(&limits);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert!(limiter.allow(ip, true));
        assert!(limiter.allow(ip, true));
        assert!(!limiter.allow(ip, true));
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::{Request, client_ip};
    use std::net::{IpAddr, SocketAddr};

    fn request(forwarded: Option<&str>) -> Request {
        let mut builder = axum::http::Request::builder();
        if let Some(value) = forwarded {
            builder = builder.header("x-forwarded-for", value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    /// The gateway's own address. Every client shares it, which is exactly
    /// why keying on it is not good enough behind a proxy.
    fn peer() -> SocketAddr {
        "172.18.0.5:41000".parse().unwrap()
    }

    /// The shipped topology: two appending hops. The client prepends a forged
    /// entry; counting from the right must skip it.
    #[test]
    fn two_trusted_hops_take_the_client_entry_not_the_forged_leftmost_one() {
        let req = request(Some("9.9.9.9, 203.0.113.7, 172.18.0.4"));
        let expected: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(client_ip(&req, peer(), 2), expected);
    }

    /// The default. An unconfigured node must not believe a header at all,
    /// including from a peer that reaches it directly.
    #[test]
    fn zero_trusted_hops_ignores_the_header() {
        let req = request(Some("9.9.9.9"));
        assert_eq!(client_ip(&req, peer(), 0), peer().ip());
    }

    /// Fewer entries than configured hops means the request did not come
    /// through the configured chain — fall back rather than trust whatever
    /// the client put there.
    #[test]
    fn a_chain_shorter_than_the_configured_hop_count_falls_back_to_the_socket_address() {
        let req = request(Some("9.9.9.9"));
        assert_eq!(client_ip(&req, peer(), 2), peer().ip());
        assert_eq!(client_ip(&request(None), peer(), 2), peer().ip());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, HolderState, Snapshot};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum TestPayload {
        Transfer { to: Address, amount: u128 },
    }

    fn test_state() -> AppState<TestPayload> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "arxium-test-rpc-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        AppState {
            mempool: Arc::new(Mutex::new(Mempool::new())),
            db: ArxiumDb::open(&dir).unwrap(),
            rpc_token: None,
            admin_token: None,
            rate_limiter: Arc::new(RateLimiter::new(&Limits::default())),
            trusted_proxy_hops: 0,
            max_nonce_gap: Limits::default().mempool_max_nonce_gap,
            gossip_tx: None,
            // Not installed as the global recorder — tests don't assert on
            // rendered metric values, just that requests still succeed.
            metrics_handle: metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
            payload_precheck: None,
            pairing: Arc::new(PairingStore::new()),
            min_stake: None,
            action_fee: None,
            weight_fee: 0,
            evidence_dir: dir.join("evidence"),
        }
    }

    fn signed_action(key: &SigningKey, nonce: u64) -> Action<TestPayload> {
        let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let to = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let mut action = Action {
            sender,
            nonce,
            signature: None,
            payload: TestPayload::Transfer { to, amount: 1 },
        };
        let sig = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(sig.to_bytes()));
        action
    }

    /// Two requests for two different addresses must produce *one* label set,
    /// naming the route template. Keying on the request path instead grows the
    /// metrics registry once per distinct address anyone asks about, and
    /// nothing ever evicts it.
    #[test]
    fn the_request_metric_is_labelled_with_the_route_template_not_the_path() {
        use tower::ServiceExt;

        let state = test_state();
        let app = Router::new()
            .route("/accounts/{address}", get(|| async { "ok" }))
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(state, guard::<TestPayload>));

        let peer = ConnectInfo("203.0.113.9:5000".parse::<SocketAddr>().unwrap());
        let request = |uri: &str| {
            axum::http::Request::builder()
                .uri(uri)
                .extension(peer)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // `with_local_recorder` installs the recorder for *this* thread, so
        // the requests have to run on it — hence a current-thread runtime.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                for address in ["arx1aaaaaaaa", "arx1bbbbbbbb"] {
                    app.clone()
                        .oneshot(request(&format!("/accounts/{address}")))
                        .await
                        .unwrap();
                }
                // A 404 must not mint a label of its own either — the guard
                // wraps the fallback too.
                app.clone()
                    .oneshot(request("/no/such/route/arx1cccccccc"))
                    .await
                    .unwrap();
            });
        });

        let rendered = handle.render();
        assert!(
            rendered.contains("path=\"/accounts/{address}\""),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("path=\"{UNMATCHED_PATH}\"")),
            "{rendered}"
        );
        assert!(!rendered.contains("arx1aaaaaaaa"), "{rendered}");
        assert!(!rendered.contains("arx1cccccccc"), "{rendered}");
    }

    /// JSON consumers (Explorer, Retracer) read `pubkey` as a `0x…` hex
    /// string; the serde default for `BlsPublicKey` is a byte array, which
    /// the Explorer rejected as a 502.
    /// `/admin/checkpoint` answers only to `admin_token` — not to
    /// `rpc_token`, not to nothing — and writes a checkpoint that reopens
    /// at the same tip.
    #[tokio::test]
    async fn admin_checkpoint_needs_the_admin_token_and_writes_a_reopenable_db() {
        use tower::ServiceExt;

        let mut state = test_state();
        state.rpc_token = Some(Arc::new("rpc".into()));
        state.admin_token = Some(Arc::new("admin".into()));
        state
            .db
            .write_batch(&Block::<TestPayload> {
                height: 0,
                parent_hash: "0xparent".into(),
                timestamp: 0,
                actions: vec![],
                tx_root: [0u8; 32],
                proposer: None,
                signature: None,
                state_root: String::new(),
                round: 0,
                round_certificate: None,
            })
            .unwrap();
        let app = Router::new()
            .route("/admin/checkpoint", post(admin_checkpoint::<TestPayload>))
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(
                state.clone(),
                admin_guard::<TestPayload>,
            ));
        let output = std::env::temp_dir().join(format!(
            "arxium-test-admin-checkpoint-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let request = |auth: Option<&str>| {
            let mut builder = axum::http::Request::builder()
                .method("POST")
                .uri("/admin/checkpoint")
                .header("content-type", "application/json");
            if let Some(auth) = auth {
                builder = builder.header("authorization", auth);
            }
            builder
                .body(axum::body::Body::from(format!(
                    "{{\"output\": {:?}}}",
                    output.display().to_string()
                )))
                .unwrap()
        };

        assert_eq!(
            app.clone().oneshot(request(None)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Some("Bearer rpc")))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "the shared rpc token must not open admin routes"
        );

        let response = app
            .clone()
            .oneshot(request(Some("Bearer admin")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["height"], 0);
        assert!(json["finalized_height"].is_null());

        let reopened = ArxiumDb::open(&output).unwrap();
        assert_eq!(reopened.get_tip_height().unwrap(), Some(0));
        drop(reopened);

        assert_eq!(
            app.oneshot(request(Some("Bearer admin")))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT,
            "never overwrite an existing path"
        );
        std::fs::remove_dir_all(&output).ok();
    }

    #[tokio::test]
    async fn bls_key_is_returned_as_hex_not_a_byte_array() {
        let state = test_state();
        let validator = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let pubkey = xc_bls::BlsPublicKey([0xAB; 48]);
        state
            .db
            .write_batches(&[
                &Block::<TestPayload> {
                    height: 0,
                    parent_hash: "0xparent".into(),
                    timestamp: 0,
                    actions: vec![],
                    tx_root: [0u8; 32],
                    proposer: None,
                    signature: None,
                    state_root: String::new(),
                    round: 0,
                    round_certificate: None,
                },
                &xc_storage::BlsKeyRegistration {
                    address: validator.clone(),
                    pubkey,
                    effective_height: 0,
                    previous_pubkey: None,
                },
            ])
            .unwrap();

        let response = get_account_bls_key::<TestPayload>(
            State(state),
            Path(validator.to_string()),
            Query(ValidatorSetQuery { height: None }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["pubkey"], format!("0x{}", "ab".repeat(48)));
    }

    #[test]
    fn pairing_store_is_single_use_and_rejects_unknown_or_reused_nonces() {
        let store = PairingStore::new();
        let validator = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let operator = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();

        assert!(matches!(
            store.submit("no-such-nonce", operator.clone()),
            SubmitOutcome::NotFound
        ));
        assert!(matches!(store.poll("no-such-nonce"), PollOutcome::NotFound));

        let nonce = store.start(validator.clone());
        assert!(matches!(store.poll(&nonce), PollOutcome::Pending));

        assert!(matches!(
            store.submit(&nonce, operator.clone()),
            SubmitOutcome::Ok(v) if v == validator
        ));
        // A second submit to the same nonce must not silently overwrite the
        // first operator — this is a QR the phone scans once.
        let other_operator = Address::from_pubkey_bytes(&[3u8; 32]).unwrap();
        assert!(matches!(
            store.submit(&nonce, other_operator),
            SubmitOutcome::AlreadyFulfilled
        ));

        match store.poll(&nonce) {
            PollOutcome::Fulfilled {
                validator: v,
                operator: o,
            } => {
                assert_eq!(v, validator);
                assert_eq!(o, operator);
            }
            _ => panic!("expected fulfilled"),
        }
        // Polling again after the fulfilled read consumed the session.
        assert!(matches!(store.poll(&nonce), PollOutcome::NotFound));
    }

    #[test]
    fn account_stake_returns_allocation_when_present_and_404_otherwise() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let alice = Address::from_pubkey_bytes(&[7u8; 32]).unwrap();

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let allocation = xc_primitives::StakeAllocation {
                master: alice.clone(),
                validator: alice.clone(),
                active_amount: 5_000,
                unbonding: None,
                created_at: 1,
                updated_at: 1,
            };
            let mut allocations = BTreeMap::new();
            allocations.insert((alice.clone(), alice.clone()), Some(allocation));
            state
                .db
                .write_batch(&xc_storage::StakeUpdates {
                    allocations,
                    validator_index: BTreeMap::new(),
                })
                .unwrap();

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn account_stakes_lists_every_validator_the_master_staked_to() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let master = Address::from_pubkey_bytes(&[10u8; 32]).unwrap();
            let other = Address::from_pubkey_bytes(&[11u8; 32]).unwrap();
            let v1 = Address::from_pubkey_bytes(&[12u8; 32]).unwrap();
            let v2 = Address::from_pubkey_bytes(&[13u8; 32]).unwrap();

            let resp = get_account_stakes(State(state.clone()), Path(master.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!([])
            );

            let alloc = |m: &Address, v: &Address, active: u128, unbonding| {
                xc_primitives::StakeAllocation {
                    master: m.clone(),
                    validator: v.clone(),
                    active_amount: active,
                    unbonding,
                    created_at: 1,
                    updated_at: 1,
                }
            };
            let mut allocations = BTreeMap::new();
            allocations.insert(
                (master.clone(), v1.clone()),
                Some(alloc(&master, &v1, 1_000, None)),
            );
            allocations.insert(
                (master.clone(), v2.clone()),
                Some(alloc(
                    &master,
                    &v2,
                    0,
                    Some(xc_primitives::Unbonding {
                        amount: 300,
                        unlock_at_height: 99,
                    }),
                )),
            );
            // Another master's row must not leak into this master's list.
            allocations.insert(
                (other.clone(), v1.clone()),
                Some(alloc(&other, &v1, 7, None)),
            );
            state
                .db
                .write_batch(&xc_storage::StakeUpdates {
                    allocations,
                    validator_index: BTreeMap::new(),
                })
                .unwrap();

            let resp = get_account_stakes(State(state.clone()), Path(master.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let rows = json.as_array().unwrap();
            assert_eq!(rows.len(), 2);
            for row in rows {
                assert_eq!(row["master"], master.to_string());
            }
            let by_validator: BTreeMap<String, &serde_json::Value> = rows
                .iter()
                .map(|r| (r["validator"].as_str().unwrap().to_string(), r))
                .collect();
            assert_eq!(by_validator[&v1.to_string()]["active_amount"], 1_000);
            assert!(by_validator[&v1.to_string()]["unbonding"].is_null());
            assert_eq!(
                by_validator[&v2.to_string()]["unbonding"]["unlock_at_height"],
                99
            );
            assert_eq!(by_validator[&v2.to_string()]["unbonding"]["amount"], 300);
        });
    }

    #[test]
    fn delegated_stake_returns_the_operators_allocation_not_the_validators_own() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let operator = Address::from_pubkey_bytes(&[8u8; 32]).unwrap();
            let validator = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();

            let resp = get_delegated_stake(
                State(state.clone()),
                Path((operator.to_string(), validator.to_string())),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let allocation = xc_primitives::StakeAllocation {
                master: operator.clone(),
                validator: validator.clone(),
                active_amount: 2_500,
                unbonding: None,
                created_at: 1,
                updated_at: 1,
            };
            let mut allocations = BTreeMap::new();
            allocations.insert((operator.clone(), validator.clone()), Some(allocation));
            state
                .db
                .write_batch(&xc_storage::StakeUpdates {
                    allocations,
                    validator_index: BTreeMap::new(),
                })
                .unwrap();

            // Querying the validator's own self-stake must not see the
            // operator's delegated allocation — different (master, validator) key.
            let resp = get_delegated_stake(
                State(state.clone()),
                Path((validator.to_string(), validator.to_string())),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = get_delegated_stake(
                State(state.clone()),
                Path((operator.to_string(), validator.to_string())),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["active_amount"], 2_500);
        });
    }

    #[test]
    fn submit_action_rejects_bad_signature_and_stale_nonce_but_accepts_valid() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let key = SigningKey::from_bytes(&[4u8; 32]);
            let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();

            // Tampering with the nonce after signing invalidates the signature.
            let mut tampered = signed_action(&key, 0);
            tampered.nonce = 1;
            let resp = submit_action(State(state.clone()), Ok(Json(tampered)))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            // Sender is already at on-chain nonce 5 — nonce 0 is a stale replay.
            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    params: Default::default(),
                    chain_name: "test".into(),
                    accounts: BTreeMap::from([(
                        sender.clone(),
                        AccountEntry {
                            balance: 1000,
                            nonce: 5,
                            ..Default::default()
                        },
                    )]),
                    validators: BTreeMap::new(),
                    boot_nodes: Vec::new(),
                    attestor: None,
                    attestor_admin: None,
                    freeze_admin: None,
                    recovery_admin: None,
                })
                .unwrap();
            let stale = signed_action(&key, 0);
            let resp = submit_action(State(state.clone()), Ok(Json(stale)))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            // Far-future nonce: can never execute until every nonce below it
            // does, and `purge_stale` never reclaims it — so it must not take
            // a mempool slot at all.
            let far_future = signed_action(&key, 5 + state.max_nonce_gap + 1);
            let resp = submit_action(State(state.clone()), Ok(Json(far_future)))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(state.mempool.lock().unwrap().len(), 0);

            // The edge of the window is still admissible.
            let edge = signed_action(&key, 5 + state.max_nonce_gap);
            let resp = submit_action(State(state.clone()), Ok(Json(edge)))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            // Correctly signed, current nonce: must be accepted into the mempool.
            let valid = signed_action(&key, 5);
            let resp = submit_action(State(state.clone()), Ok(Json(valid)))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            assert_eq!(state.mempool.lock().unwrap().len(), 2);
        });
    }

    /// Two issuers' `gold` on one chain: every asset endpoint resolves by
    /// ref and hands back the right one, `?issuer=` narrows the listing, and
    /// the alias route derives the ref for an unclaimed slug.
    #[test]
    fn asset_endpoints_resolve_by_ref_not_slug() {
        use xc_storage::AssetBalanceUpdates;

        async fn json(resp: Response) -> serde_json::Value {
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
            let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
            let mut alice_gold = Asset::new("gold", alice.clone(), true);
            alice_gold.symbol = "GOLD".into();
            let bob_gold = Asset::new("gold", bob.clone(), false);
            let balances = AssetBalanceUpdates(BTreeMap::from([
                ((alice_gold.asset_ref.clone(), bob.clone()), 7u128),
                ((bob_gold.asset_ref.clone(), bob.clone()), 3u128),
            ]));
            let index = state
                .db
                .asset_index_updates(&[alice_gold.clone(), bob_gold.clone()], &balances)
                .unwrap();
            state
                .db
                .write_batches(&[&alice_gold, &bob_gold, &balances, &index])
                .unwrap();

            let resp = get_asset(State(state.clone()), Path(alice_gold.asset_ref.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            assert_eq!(body["ref"], alice_gold.asset_ref.to_string());
            assert_eq!(body["asset_id"], "gold");
            assert_eq!(body["symbol"], "GOLD");
            assert_eq!(body["issuer"], alice.to_string());
            assert_eq!(body["issuer_attested"], false);
            assert_eq!(body["holders"], 1);

            // The slug is not a route: a non-ref path segment is a 400.
            let resp = get_asset(State(state.clone()), Path("gold".into()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            let resp = get_assets(
                State(state.clone()),
                Query(AssetsQuery {
                    issuer: Some(bob.to_string()),
                }),
            )
            .await
            .into_response();
            let body = json(resp).await;
            assert_eq!(body.as_array().unwrap().len(), 1);
            assert_eq!(body[0]["ref"], bob_gold.asset_ref.to_string());
            let resp = get_assets(State(state.clone()), Query(AssetsQuery { issuer: None }))
                .await
                .into_response();
            assert_eq!(json(resp).await.as_array().unwrap().len(), 2);

            let resp =
                get_asset_alias(State(state.clone()), Path((bob.to_string(), "gold".into())))
                    .await
                    .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(json(resp).await["ref"], bob_gold.asset_ref.to_string());
            let resp = get_asset_alias(
                State(state.clone()),
                Path((bob.to_string(), "silver".into())),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                json(resp).await["ref"],
                AssetRef::derive(&bob, "silver").unwrap().to_string()
            );

            let resp = get_account_asset_balance(
                State(state.clone()),
                Path((bob.to_string(), alice_gold.asset_ref.to_string())),
            )
            .await
            .into_response();
            let body = json(resp).await;
            assert_eq!(body["balance"], 7);
            assert_eq!(body["issuer"], alice.to_string());
            let resp = get_account_assets(State(state.clone()), Path(bob.to_string()))
                .await
                .into_response();
            let body = json(resp).await;
            let rows = body.as_array().unwrap();
            assert_eq!(rows.len(), 2);
            let bobs = rows
                .iter()
                .find(|r| r["ref"] == bob_gold.asset_ref.to_string())
                .unwrap();
            assert_eq!(bobs["balance"], 3);
        });
    }

    /// The proof endpoint round-trips through the same verifier
    /// `arx-verify` uses, against the block it names, for both a present
    /// and an absent key.
    #[test]
    fn state_proof_verifies_against_the_named_block_root() {
        use xc_storage::AccountUpdates;

        async fn json(resp: Response) -> serde_json::Value {
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
            let nobody = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
            let accounts = AccountUpdates(BTreeMap::from([(
                alice.clone(),
                xc_primitives::AccountEntry {
                    balance: 42,
                    ..Default::default()
                },
            )]));
            state.db.write_batch(&accounts).unwrap();
            let genesis = Block::<TestPayload> {
                state_root: state.db.compute_state_root(&[]).unwrap(),
                ..Block::genesis(0)
            };
            state.db.write_batch(&genesis).unwrap();

            for (who, expect_value) in [(&alice, Some(42u64)), (&nobody, None)] {
                let resp = get_account_proof(State(state.clone()), Path(who.to_string()))
                    .await
                    .into_response();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = json(resp).await;
                assert_eq!(body["height"], 0);
                assert_eq!(body["state_root"], genesis.state_root);
                assert_eq!(body["block_hash"], genesis.hash().to_string());
                assert_eq!(body["value"]["balance"].as_u64(), expect_value);
                let proof: xc_artifact::StateProof =
                    serde_json::from_value(body["proof"].clone()).unwrap();
                let root: [u8; 32] = hex::decode(genesis.state_root.trim_start_matches("0x"))
                    .unwrap()
                    .try_into()
                    .unwrap();
                xc_artifact::verify_state_proof(root, &proof)
                    .expect("proof verifies against the named root");
                assert_eq!(proof.value.is_some(), expect_value.is_some());
                // ... and not against any other root.
                assert!(xc_artifact::verify_state_proof([0xAA; 32], &proof).is_err());
            }
        });
    }

    #[test]
    fn account_assets_reports_exact_holder_eligibility_and_u128_lock() {
        use xc_storage::{AssetBalanceUpdates, HolderStateUpdates};

        #[derive(Deserialize)]
        struct EligibilityFields {
            holder_frozen: bool,
            frozen_amount: u128,
            transfer_eligible: bool,
            eligibility_reason: String,
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let issuer = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
            let holder = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
            let asset = Asset::new("locked", issuer, false);
            let balances = AssetBalanceUpdates(BTreeMap::from([(
                (asset.asset_ref.clone(), holder.clone()),
                u128::MAX,
            )]));
            let holder_states = HolderStateUpdates(BTreeMap::from([(
                (asset.asset_ref.clone(), holder.clone()),
                HolderState {
                    frozen: false,
                    frozen_amount: u128::MAX,
                },
            )]));
            let index = state
                .db
                .asset_index_updates(std::slice::from_ref(&asset), &balances)
                .unwrap();
            state
                .db
                .write_batches(&[&asset, &balances, &holder_states, &index])
                .unwrap();

            let resp = get_account_assets(State(state), Path(holder.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(
                text.contains(&format!("\"frozen_amount\":{}", u128::MAX)),
                "exact u128 JSON: {text}"
            );
            let rows: Vec<EligibilityFields> = serde_json::from_slice(&body).unwrap();
            assert!(!rows[0].holder_frozen);
            assert_eq!(rows[0].frozen_amount, u128::MAX);
            assert!(!rows[0].transfer_eligible);
            assert_eq!(rows[0].eligibility_reason, "no_transferable_balance");
        });
    }

    #[test]
    fn min_stake_reports_404_when_unset_and_the_value_when_set() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let resp = get_min_stake(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let mut state = state;
            state.min_stake = Some(1_000);
            let resp = get_min_stake(State(state)).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["min_stake"], 1_000);
        });
    }

    #[test]
    fn action_fee_reports_404_when_unset_and_the_value_when_set() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let resp = get_action_fee(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let mut state = state;
            state.action_fee = Some(10);
            let resp = get_action_fee(State(state)).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["action_fee"], 10);
        });
    }

    #[test]
    fn status_reports_chain_name_and_tip_before_and_after_a_block() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();

            // No genesis written yet: nothing to report.
            let resp = get_status(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            let genesis: xc_primitives::Block<TestPayload> = xc_primitives::Block::genesis(0);
            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    params: Default::default(),
                    chain_name: "test-chain".into(),
                    accounts: BTreeMap::new(),
                    validators: BTreeMap::new(),
                    boot_nodes: Vec::new(),
                    attestor: None,
                    attestor_admin: None,
                    freeze_admin: None,
                    recovery_admin: None,
                })
                .unwrap();
            state.db.write_batch(&genesis).unwrap();
            state
                .db
                .write_batch(&xc_storage::GenesisHash(genesis.state_root.clone()))
                .unwrap();

            let resp = get_status(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["chain_name"], "test-chain");
            assert_eq!(json["tip_height"], 0);
            assert_eq!(json["tip_hash"], genesis.hash().to_string());
            assert_eq!(json["genesis_hash"], genesis.state_root);
        });
    }

    fn block_with_action(
        height: u64,
        action: Action<TestPayload>,
    ) -> xc_primitives::Block<TestPayload> {
        let mut block: xc_primitives::Block<TestPayload> = xc_primitives::Block::genesis(height);
        block.height = height;
        block.actions = vec![action];
        block
    }

    #[test]
    fn blocks_range_and_by_height_and_by_hash() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let key = SigningKey::from_bytes(&[4u8; 32]);
            for h in 0..3u64 {
                let block = block_with_action(h, signed_action(&key, h));
                state.db.write_batch(&block).unwrap();
            }

            let resp = get_blocks(
                State(state.clone()),
                Query(BlockRangeQuery { from: 0, to: 2 }),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.as_array().unwrap().len(), 3);

            let resp = get_block_by_height(State(state.clone()), Path(1))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_height(State(state.clone()), Path(99))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let target_hash = state
                .db
                .get_block::<TestPayload>(1)
                .unwrap()
                .unwrap()
                .hash();
            let resp = get_block_by_hash(State(state.clone()), Path(target_hash.to_string()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_hash(State(state.clone()), Path("0xnope".into()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn evidence_list_and_fetch_serve_the_evidence_dir_and_reject_path_traversal() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();

            // No evidence directory yet just means no faults observed so far.
            let resp = get_evidence_list(State(state.clone()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json.as_array().unwrap().is_empty());

            std::fs::create_dir_all(&state.evidence_dir).unwrap();
            std::fs::write(state.evidence_dir.join("fault-1.json"), b"{\"ok\":true}").unwrap();

            let resp = get_evidence_list(State(state.clone()))
                .await
                .into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.as_array().unwrap(), &["fault-1.json"]);

            let resp = get_evidence_by_id(State(state.clone()), Path("fault-1.json".into()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"{\"ok\":true}");

            let resp = get_evidence_by_id(State(state.clone()), Path("no-such-file.json".into()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = get_evidence_by_id(State(state.clone()), Path("../secrets.json".into()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn search_resolves_each_kind() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let key = SigningKey::from_bytes(&[4u8; 32]);
            let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
            let mut last_sig = String::new();
            for h in 0..3u64 {
                let action = signed_action(&key, h);
                last_sig = action.signature.clone().unwrap();
                let block = block_with_action(h, action);
                state.db.write_batch(&block).unwrap();
            }

            // search by height
            let resp = search(State(state.clone()), Query(SearchQuery { q: "1".into() }))
                .await
                .into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["kind"], "block");
            assert_eq!(json["height"], 1);

            // search by a numeric height that doesn't exist on chain
            let resp = search(
                State(state.clone()),
                Query(SearchQuery { q: "99999".into() }),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            // search by address
            let resp = search(
                State(state.clone()),
                Query(SearchQuery {
                    q: sender.to_string(),
                }),
            )
            .await
            .into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["kind"], "account");

            // search by action signature
            let resp = search(State(state.clone()), Query(SearchQuery { q: last_sig }))
                .await
                .into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["kind"], "action");

            // search miss
            let resp = search(
                State(state.clone()),
                Query(SearchQuery {
                    q: "nonsense".into(),
                }),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    /// The endpoint has to distinguish "young chain, nothing final yet" from
    /// "this set can never finalize anything", because the second is a real
    /// configuration failure whose only other symptom is a warn per dropped
    /// vote. A validator set with no registered BLS keys is exactly that case
    /// — and it is what a chain started from a genesis spec looks like, since
    /// genesis carries no keys.
    #[test]
    fn finality_reports_why_a_set_cannot_reach_quorum() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let validator = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();

            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    params: Default::default(),
                    chain_name: "test-chain".into(),
                    accounts: BTreeMap::new(),
                    validators: BTreeMap::new(),
                    boot_nodes: Vec::new(),
                    attestor: None,
                    attestor_admin: None,
                    freeze_admin: None,
                    recovery_admin: None,
                })
                .unwrap();
            let genesis: xc_primitives::Block<TestPayload> = xc_primitives::Block::genesis(0);
            state.db.write_batch(&genesis).unwrap();
            state
                .db
                .write_batch(&xc_storage::ValidatorSetSnapshot::equal_power(
                    0,
                    &[validator.clone()],
                ))
                .unwrap();

            let resp = get_finality::<TestPayload>(State(state.clone()))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            // Null, not absent — a client must tell "nothing final yet" from
            // "this node is too old to report finality".
            assert!(json["finalized_height"].is_null());
            assert_eq!(json["validators"], 1);
            assert_eq!(json["validators_with_bls_key"], 0);
            assert_eq!(json["quorum"], QUORUM_POWER);
            assert_eq!(json["voting_power_with_bls_key"], 0);
            assert_eq!(
                json["quorum_reachable"], false,
                "a set with no BLS keys can never finalize, and must say so",
            );

            // Register the key and the same set becomes able to finalize.
            state
                .db
                .write_batch(&xc_storage::BlsKeyRegistration {
                    address: validator.clone(),
                    pubkey: xc_bls::BlsPublicKey([7u8; 48]),
                    effective_height: 0,
                    previous_pubkey: None,
                })
                .unwrap();

            let resp = get_finality::<TestPayload>(State(state.clone()))
                .await
                .into_response();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["validators_with_bls_key"], 1);
            assert_eq!(json["quorum_reachable"], true);
        });
    }

    /// `finalized` is injected into the block's own JSON rather than nesting
    /// the block under a wrapper, so every existing consumer keeps reading the
    /// fields it already reads. This pins both halves: the flag is present and
    /// correct, and the block's own fields are untouched.
    #[test]
    fn block_reads_carry_a_finalized_flag_without_reshaping_the_block() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let genesis: xc_primitives::Block<TestPayload> = xc_primitives::Block::genesis(0);
            state.db.write_batch(&genesis).unwrap();

            let resp = get_block_by_height::<TestPayload>(State(state.clone()), Path(0))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            assert_eq!(json["finalized"], false, "no certificate written yet");
            // The wire hash and per-action JSON payloads ride alongside, so an
            // HTTP-only reader needs neither our bincode layout nor `P`.
            assert_eq!(json["hash"], genesis.hash().to_string());
            // Still flat, still the block's own fields.
            assert_eq!(json["height"], 0);
            assert!(json["timestamp"].is_number());
            assert!(json["actions"].is_array());

            state
                .db
                .write_batch(&xc_storage::FinalityRecord {
                    height: 0,
                    block_hash: genesis.hash(),
                    signers: vec![Address::from_pubkey_bytes(&[9u8; 32]).unwrap()],
                    aggregate_signature: xc_bls::BlsSignature([3u8; 96]),
                    ep: [0u8; 32],
                })
                .unwrap();

            let resp = get_block_by_height::<TestPayload>(State(state.clone()), Path(0))
                .await
                .into_response();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["finalized"], true);
        });
    }
}
