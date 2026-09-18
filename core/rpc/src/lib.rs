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
    Action, Address, Asset, AssetRef, Block, Hash32, Limits, QUORUM_POWER, TOTAL_VOTING_POWER, signed_power,
};
use xc_storage::{ArxiumDb, StorageError};

mod error;
use error::ApiError;

/// `Address::parse`, mapped to the 400 every handler already gave it.
fn parse_address(s: &str) -> Result<Address, ApiError> {
    Address::parse(s).map_err(|err| ApiError::BadRequest(err.to_string()))
}

/// Resolves a `?height=` query param against the tip, rejecting one above it
/// — answering with the tip's set would look like data rather than the
/// caller mistake it is. `None` means "as of the tip".
fn resolve_height(requested: Option<u64>, tip_height: u64) -> Result<u64, ApiError> {
    match requested {
        Some(h) if h > tip_height => {
            Err(ApiError::BadRequest(format!("height {h} is above the chain tip {tip_height}")))
        }
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

        let max = if is_write { self.max_writes } else { self.max_reads };
        let entry = hits.entry((ip, is_write)).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }
}

// How long an `arxd pair`-started session stays claimable before the
// operator has to re-run it. Long enough to scan a QR without rushing,
// short enough that a screenshotted/leaked QR is useless soon after.
const PAIRING_TTL: Duration = Duration::from_secs(300);

/// A validator's local `arxd pair` process registers one of these (see
/// `start_pairing`), the app that scans the resulting QR fills in `operator`
/// (see `submit_pairing`), and `arxd pair` polls for it (see `poll_pairing`)
/// to learn which address to self-sign `AuthorizeOperator` for — without the
/// validator's own signing key ever leaving the node it runs on. Purely
/// in-memory and single-node: a session is meaningless anywhere but the RPC
/// instance that minted its nonce.
struct PairingSession {
    validator: Address,
    operator: Option<Address>,
    created_at: Instant,
}

enum SubmitOutcome {
    Ok(Address),
    NotFound,
    AlreadyFulfilled,
}

struct PairingStore {
    sessions: Mutex<HashMap<String, PairingSession>>,
}

impl PairingStore {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn start(&self, validator: Address) -> String {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Bounded and rare enough (one operator action, not a hot path) to
        // sweep on every insert rather than needing a size threshold like
        // `RateLimiter` does.
        sessions.retain(|_, s| now.duration_since(s.created_at) <= PAIRING_TTL);

        let mut nonce_bytes = [0u8; 16];
        rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        sessions.insert(
            nonce.clone(),
            PairingSession {
                validator,
                operator: None,
                created_at: now,
            },
        );
        nonce
    }

    fn submit(&self, nonce: &str, operator: Address) -> SubmitOutcome {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = sessions.get_mut(nonce) else {
            return SubmitOutcome::NotFound;
        };
        if Instant::now().duration_since(session.created_at) > PAIRING_TTL {
            sessions.remove(nonce);
            return SubmitOutcome::NotFound;
        }
        if session.operator.is_some() {
            return SubmitOutcome::AlreadyFulfilled;
        }
        session.operator = Some(operator);
        SubmitOutcome::Ok(session.validator.clone())
    }

    /// Consumes (removes) the session once it's fulfilled, so a session can
    /// only ever be claimed once even within its TTL.
    fn poll(&self, nonce: &str) -> PollOutcome {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = sessions.get(nonce) else {
            return PollOutcome::NotFound;
        };
        if Instant::now().duration_since(session.created_at) > PAIRING_TTL {
            sessions.remove(nonce);
            return PollOutcome::NotFound;
        }
        match &session.operator {
            Some(operator) => {
                let fulfilled = PollOutcome::Fulfilled {
                    validator: session.validator.clone(),
                    operator: operator.clone(),
                };
                sessions.remove(nonce);
                fulfilled
            }
            None => PollOutcome::Pending,
        }
    }
}

enum PollOutcome {
    Fulfilled { validator: Address, operator: Address },
    Pending,
    NotFound,
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
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_PATH.to_string(), |matched| matched.as_str().to_string());
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

/// Bearer check for `/admin/*` against `admin_token`. Only ever mounted
/// when the token is set, so a missing token here is a wiring bug, not an
/// open door — it still fails closed.
async fn admin_guard<P: Payload>(
    State(state): State<AppState<P>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_PATH.to_string(), |matched| matched.as_str().to_string());
    let authorized = state.admin_token.as_ref().is_some_and(|token| {
        let expected = format!("Bearer {token}");
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.len() == expected.len() && value.as_bytes().ct_eq(expected.as_bytes()).into()
            })
    });
    if !authorized {
        record_request(&path, StatusCode::UNAUTHORIZED);
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let response = next.run(req).await;
    record_request(&path, response.status());
    response
}

#[derive(serde::Deserialize)]
struct CheckpointRequest {
    /// Server-local directory to write into. Must not already exist —
    /// RocksDB refuses to checkpoint into an existing path rather than merge.
    output: PathBuf,
}

#[derive(Serialize)]
struct CheckpointResponse {
    /// Tip at the time of the request. The checkpoint is of the live DB and
    /// may include blocks past `finalized_height`; a restore from it plus a
    /// resync reconciles anything provisional.
    height: u64,
    finalized_height: Option<u64>,
    path: PathBuf,
}

/// `POST /admin/checkpoint {"output": "<path>"}` — a consistent RocksDB
/// checkpoint of the running node, without stopping it. Same primitive as
/// `arxd snapshot`, which needs the node stopped only because it opens a
/// second DB handle; from inside the process that constraint doesn't apply.
async fn admin_checkpoint<P: Payload>(
    State(state): State<AppState<P>>,
    body: Result<Json<CheckpointRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::BadRequest(err.to_string()))?;
    if !body.output.is_absolute() {
        return Err(ApiError::BadRequest("output must be an absolute path".to_string()));
    }
    if body.output.exists() {
        return Err(ApiError::Conflict("output path already exists".to_string()));
    }
    let height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let finalized_height = state.db.get_finalized_height().unwrap_or_default();
    let db = state.db.clone();
    let output = body.output.clone();
    // Hard-links the SSTs and copies the live WAL — file I/O proportional
    // to the WAL, so off the async runtime.
    let result = tokio::task::spawn_blocking(move || db.export_checkpoint(&output)).await;
    match result {
        Ok(Ok(())) => {
            info!("wrote checkpoint at height {height} to {}", body.output.display());
            Ok(Json(CheckpointResponse { height, finalized_height, path: body.output }).into_response())
        }
        Ok(Err(err)) => {
            warn!("checkpoint to {} failed: {err}", body.output.display());
            Ok((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
        }
        Err(err) => Err(ApiError::internal(anyhow::anyhow!("checkpoint task panicked: {err}"))),
    }
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
    if rpc_token.is_none() && bind_addr.parse::<IpAddr>().is_ok_and(|ip| !ip.is_loopback()) {
        warn!("RPC bound to {bind_addr} with no --rpc-token: anyone who can reach it can submit actions");
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
        && let Err(err) = precheck(&action, &state.db) {
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

#[derive(serde::Deserialize)]
struct StartPairingRequest {
    validator: Address,
}

#[derive(Serialize)]
struct StartPairingResponse {
    nonce: String,
}

/// Called by an `arxd pair` process (never by the app) to register a
/// pairing session for `validator` — the node it runs on holds that
/// validator's signing key and never hands it over; this just gives the app
/// a nonce to fill in with the operator address it wants authorized. Behind
/// the same bearer-token guard as `/actions`.
async fn start_pairing<P: Payload>(
    State(state): State<AppState<P>>,
    body: Result<Json<StartPairingRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(json) => json,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let nonce = state.pairing.start(body.validator);
    Json(StartPairingResponse { nonce }).into_response()
}

#[derive(serde::Deserialize)]
struct SubmitPairingRequest {
    operator: Address,
}

/// Called by the app once it's scanned an `arxd pair` QR, naming the
/// address it wants authorized as that validator's operator. Doesn't
/// authorize anything by itself — `arxd pair` still has to poll this up
/// (`poll_pairing`) and self-sign the actual `AuthorizeOperator` action.
async fn submit_pairing<P: Payload>(
    State(state): State<AppState<P>>,
    Path(nonce): Path<String>,
    body: Result<Json<SubmitPairingRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(json) => json,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    match state.pairing.submit(&nonce, body.operator) {
        SubmitOutcome::Ok(_validator) => StatusCode::OK.into_response(),
        SubmitOutcome::NotFound => {
            (StatusCode::NOT_FOUND, "unknown or expired pairing session").into_response()
        }
        SubmitOutcome::AlreadyFulfilled => {
            (StatusCode::CONFLICT, "pairing session already claimed").into_response()
        }
    }
}

#[derive(Serialize)]
struct PollPairingResponse {
    validator: Address,
    operator: Address,
}

/// Polled by `arxd pair` while it waits for `submit_pairing`. Consumes the
/// session on the first successful read — see `PairingStore::poll`.
async fn poll_pairing<P: Payload>(
    State(state): State<AppState<P>>,
    Path(nonce): Path<String>,
) -> Response {
    match state.pairing.poll(&nonce) {
        PollOutcome::Fulfilled { validator, operator } => {
            Json(PollPairingResponse { validator, operator }).into_response()
        }
        PollOutcome::Pending => StatusCode::ACCEPTED.into_response(),
        PollOutcome::NotFound => {
            (StatusCode::NOT_FOUND, "unknown or expired pairing session").into_response()
        }
    }
}

/// Chain-wide health: name, tip height/hash. No per-account or per-action
/// state, so unlike other routes it can't 404 — an initialized node always
/// has at least the genesis block.
async fn get_status<P: Payload>(State(state): State<AppState<P>>) -> Result<Response, ApiError> {
    let chain_name = state.db.get_chain_name()?.ok_or(ApiError::ServiceUnavailable)?;
    let tip_height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let tip_hash = state
        .db
        .get_block::<P>(tip_height)?
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("tip height {tip_height} recorded but block is missing")))?
        .hash();
    let genesis_hash = state.db.genesis_hash()?.ok_or(ApiError::ServiceUnavailable)?;

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
async fn get_action_fee<P: Payload>(State(state): State<AppState<P>>) -> Result<Response, ApiError> {
    let action_fee = state.action_fee.ok_or(ApiError::NotFound)?;
    let max_block_weight = state.db.chain_params()?.max_block_weight;
    Ok(Json(serde_json::json!({
        "action_fee": action_fee,
        "weight_fee": state.weight_fee,
        "max_block_weight": max_block_weight,
    }))
    .into_response())
}

async fn get_account<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<xc_primitives::AccountEntry>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(state.db.get_account(&address)?.ok_or(ApiError::NotFound)?))
}

/// EIP-1186-shaped state proof: one key's value (or proven absence) under a
/// *certified* state root, plus everything a party with no node needs to
/// check it — the block whose `state_root` it is, and the finality
/// certificate over that block. `arx-verify state-proof` does the check.
///
/// Served against the final watermark, never the tip: a proof against a
/// provisional root is a proof of something a reorg can undo.
#[derive(Serialize)]
struct StateProofResponse {
    /// The raw state key, as `xc_circuit::KeySpec::encode` produces it.
    key: String,
    /// Decoded value, or `null` for a non-inclusion proof.
    value: serde_json::Value,
    /// Compressed sibling path (`xc_artifact::StateProof`); `proof.value`
    /// is the exact bincode bytes the leaf commits to.
    proof: xc_artifact::StateProof,
    height: u64,
    state_root: String,
    block_hash: String,
    /// Inputs to the PoE commitment the certificate signs over, so a
    /// verifier can bind `state_root` to `finality.ep` without trusting
    /// this node: `ep = block_ep(parent_state_root, block.tx_root,
    /// state_root, weight_used)`.
    parent_state_root: String,
    weight_used: u64,
    block: serde_json::Value,
    /// `null` only on a chain that has not finalized anything yet (then
    /// `height` is genesis and the proof is against the genesis root).
    finality: Option<xc_storage::FinalityRecord>,
}

fn state_proof<P: Payload, K: xc_circuit::KeySpec>(
    db: &ArxiumDb,
    key: &K,
) -> Result<StateProofResponse, StorageError> {
    let height = db.get_final_watermark()?;
    let block: Block<P> = db.get_block(height)?.ok_or(StorageError::CorruptedMeta)?;
    let parent_state_root = if height == 0 {
        String::new()
    } else {
        db.get_block::<P>(height - 1)?.map(|b| b.state_root).unwrap_or_default()
    };
    let raw_key = key.encode();
    let inclusion = db.prove(&raw_key, &block.state_root)?;
    let value = match &inclusion.value {
        Some(bytes) => {
            let (decoded, _): (K::Value, usize) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
            serde_json::to_value(decoded).unwrap_or(serde_json::Value::Null)
        }
        None => serde_json::Value::Null,
    };
    let proof = inclusion.into_state_proof();
    Ok(StateProofResponse {
        key: String::from_utf8_lossy(&raw_key).into_owned(),
        value,
        proof,
        height,
        state_root: block.state_root.clone(),
        block_hash: block.hash().to_string(),
        parent_state_root,
        weight_used: db.get_block_weight(height)?,
        block: serde_json::to_value(&block).unwrap_or(serde_json::Value::Null),
        finality: db.get_finality_record(height)?,
    })
}

fn state_proof_response<P: Payload, K: xc_circuit::KeySpec>(
    db: &ArxiumDb,
    key: &K,
) -> Result<Json<StateProofResponse>, ApiError> {
    Ok(Json(state_proof::<P, K>(db, key)?))
}

async fn get_account_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    state_proof_response::<P, _>(&state.db, &xc_circuit::AccountKey(&address))
}

async fn get_validator_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    state_proof_response::<P, _>(&state.db, &xc_circuit::ValidatorStatusKey(&address))
}

async fn get_account_asset_balance_proof<P: Payload>(
    State(state): State<AppState<P>>,
    Path((address, asset_ref)): Path<(String, String)>,
) -> Result<Json<StateProofResponse>, ApiError> {
    let address = parse_address(&address)?;
    let asset_ref = parse_ref(&asset_ref)?;
    state_proof_response::<P, _>(&state.db, &xc_circuit::AssetBalanceKey { asset: &asset_ref, owner: &address })
}

/// The genesis state root bound into every BLS finality signature. External
/// verifiers must pin this value rather than infer network identity from a
/// mutable chain-name label.
async fn get_genesis_hash<P: Payload>(State(state): State<AppState<P>>) -> Result<Response, ApiError> {
    let genesis_hash = state.db.genesis_hash()?.ok_or(ApiError::ServiceUnavailable)?;
    Ok(Json(serde_json::json!({ "genesis_hash": genesis_hash })).into_response())
}

async fn get_account_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<xc_primitives::StakeAllocation>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(state.db.get_stake_allocation(&address, &address)?.ok_or(ApiError::NotFound)?))
}

/// A delegated stake allocation: `master` need not equal `validator` (unlike
/// `GET /accounts/{address}/stake`, the self-stake case) — this is how an
/// operator/app looks up how much it has staked on a validator's behalf.
async fn get_delegated_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path((master, validator)): Path<(String, String)>,
) -> Result<Json<xc_primitives::StakeAllocation>, ApiError> {
    let master = parse_address(&master)?;
    let validator = parse_address(&validator)?;
    Ok(Json(state.db.get_stake_allocation(&master, &validator)?.ok_or(ApiError::NotFound)?))
}

/// Whether `address` has a BLS key registered for finality precommit voting
/// (`ActionPayload::RegisterBlsKey`) — a validator without one can be in the
/// validator set but its votes are silently dropped by `arxd/finality`.
async fn get_account_bls_key<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Response, ApiError> {
    let address = parse_address(&address)?;

    let tip_height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;

    // Certificates must be checked against the key registered at their height.
    // Reading the current key after rotation would incorrectly reject an old
    // valid certificate or accept a forged historical one.
    let pubkey = state.db.get_bls_pubkey_at(&address, height)?.ok_or(ApiError::NotFound)?;
    // Hex, not the serde byte array: every JSON consumer (Explorer, Retracer)
    // expects the same `0x…` form as `voter_pubkey` in the fault report.
    Ok(Json(serde_json::json!({ "pubkey": format!("0x{}", hex::encode(pubkey.0)) })).into_response())
}

/// One row of `GET /accounts/{address}/assets`.
///
/// Carries the registry fields alongside the balance rather than just the ref:
/// a wallet has to know whether an asset is compliance-gated before it can
/// tell the holder why a transfer would be refused, and making that a second
/// request per asset would put an N+1 on the one screen that lists them all.
///
/// `frozen` and `decimals` are here for the same reason as
/// `compliance_required`: a frozen asset refuses every transfer, so a wallet
/// that can't see the flag can only report the failure after the fact, and
/// `balance` is a raw integer that cannot be rendered at all without the
/// scale. `symbol`/`name` are what the wallet shows next to the truncated
/// `ref`; they identify nothing. The rest of the record (claims,
/// jurisdictions, supply) is only needed on an asset's own screen, which can
/// fetch `GET /assets/{ref}`. `transfer_eligible` means this holder can send
/// at least one base unit to an otherwise eligible recipient; recipient and
/// nonce checks necessarily happen when the transfer is submitted.
#[derive(serde::Serialize)]
struct AccountAssetBalance {
    #[serde(rename = "ref")]
    asset_ref: AssetRef,
    asset_id: String,
    symbol: String,
    name: String,
    issuer: String,
    issuer_attested: bool,
    compliance_required: bool,
    frozen: bool,
    holder_frozen: bool,
    frozen_amount: u128,
    transfer_eligible: bool,
    eligibility_reason: &'static str,
    decimals: u8,
    balance: u128,
}

impl AccountAssetBalance {
    fn new(db: &ArxiumDb, address: &Address, asset: Asset, balance: u128) -> Result<Self, StorageError> {
        let issuer_attested = issuer_attested(db, &asset.issuer)?;
        let holder_state = db.get_holder_state(&asset.asset_ref, address)?;
        let eligibility = circuit_rwa_asset::transfer_eligibility(db, &asset, address, balance)?;
        Ok(Self {
            asset_ref: asset.asset_ref,
            asset_id: asset.asset_id,
            symbol: asset.symbol,
            name: asset.name,
            issuer: asset.issuer.to_string(),
            issuer_attested,
            compliance_required: asset.compliance_required,
            frozen: asset.frozen,
            holder_frozen: holder_state.frozen,
            frozen_amount: holder_state.frozen_amount,
            transfer_eligible: eligibility.is_eligible(),
            eligibility_reason: eligibility.reason(),
            decimals: asset.decimals,
            balance,
        })
    }
}

/// The trust anchor a client shows beside a symbol: whether the issuer holds
/// a live attestation. Symbols are not unique, so this — not the ticker — is
/// what tells two `GOLD`s apart in an interface. Same rule as
/// `circuit_rwa_asset::is_attested`.
fn issuer_attested(db: &ArxiumDb, issuer: &Address) -> Result<bool, StorageError> {
    circuit_rwa_asset::is_attested(db, issuer)
}

fn parse_ref(s: &str) -> Result<AssetRef, ApiError> {
    AssetRef::parse(s).map_err(|err| ApiError::BadRequest(err.to_string()))
}

/// One row of an asset's cap table: balance plus the issuer's freeze state.
#[derive(Serialize)]
struct AssetHolderRow {
    address: Address,
    balance: u128,
    frozen: bool,
    frozen_amount: u128,
}

/// The cap table — every address with a non-zero balance (from the
/// `meta:asset_holders` index) with its balance and holder state.
async fn get_asset_holders<P: Payload>(
    State(state): State<AppState<P>>,
    Path(asset_ref): Path<String>,
) -> Result<Json<Vec<AssetHolderRow>>, ApiError> {
    let asset_ref = parse_ref(&asset_ref)?;
    state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    let holders = state.db.get_asset_holders(&asset_ref)?;
    let mut rows = Vec::with_capacity(holders.len());
    for address in holders {
        let balance = state.db.get_asset_balance(&asset_ref, &address)?;
        let holder_state = state.db.get_holder_state(&asset_ref, &address)?;
        rows.push(AssetHolderRow { address, balance, frozen: holder_state.frozen, frozen_amount: holder_state.frozen_amount });
    }
    Ok(Json(rows))
}

/// Every regulated asset `address` holds a balance row for.
///
/// Includes rows that have gone to zero — a balance row is never deleted, and
/// "you held this and now hold none" is a different statement from "you never
/// held this". Answered from the `meta:account_assets:` index; the balance
/// keys themselves are ordered `{asset_ref}:{owner}` and cannot be scanned by
/// owner.
async fn get_account_assets<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<AccountAssetBalance>>, ApiError> {
    let address = parse_address(&address)?;
    let refs = state.db.get_account_assets(&address)?;

    let mut balances = Vec::with_capacity(refs.len());
    for asset_ref in refs {
        // Indexed but unregistered is impossible through the normal write
        // path (both rows land in one atomic batch), so skip rather than
        // fail the whole listing.
        let Some(asset) = state.db.get_asset(&asset_ref)? else { continue };
        let balance = state.db.get_asset_balance(&asset_ref, &address)?;
        balances.push(AccountAssetBalance::new(&state.db, &address, asset, balance)?);
    }

    Ok(Json(balances))
}

/// `address`'s balance of one asset. 404 when the asset was never registered,
/// which is a different answer from a registered asset held at zero — the
/// latter is a legitimate 200 with `balance: 0`.
async fn get_account_asset_balance<P: Payload>(
    State(state): State<AppState<P>>,
    Path((address, asset_ref)): Path<(String, String)>,
) -> Result<Json<AccountAssetBalance>, ApiError> {
    let address = parse_address(&address)?;
    let asset_ref = parse_ref(&asset_ref)?;
    let asset = state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    let balance = state.db.get_asset_balance(&asset_ref, &address)?;
    Ok(Json(AccountAssetBalance::new(&state.db, &address, asset, balance)?))
}

/// The registry record plus what a client needs to render it safely without
/// a second call: `holders` (the cap-table size) and `issuer_attested`. The
/// record's own `asset_ref` field is surfaced as `ref`.
#[derive(Serialize)]
struct AssetResponse {
    #[serde(rename = "ref")]
    asset_ref: AssetRef,
    #[serde(flatten)]
    asset: Asset,
    issuer_attested: bool,
    holders: usize,
}

fn asset_response(db: &ArxiumDb, asset: Asset) -> Result<AssetResponse, StorageError> {
    let holders = db.get_asset_holders(&asset.asset_ref)?.len();
    let issuer_attested = issuer_attested(db, &asset.issuer)?;
    Ok(AssetResponse { asset_ref: asset.asset_ref.clone(), asset, issuer_attested, holders })
}

#[derive(serde::Deserialize)]
struct AssetsQuery {
    /// Restrict the listing to one issuer's assets.
    issuer: Option<String>,
}

/// Every asset registered on this chain, in registration order — or, with
/// `?issuer=`, just that issuer's.
async fn get_assets<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<AssetsQuery>,
) -> Result<Json<Vec<AssetResponse>>, ApiError> {
    let issuer = query
        .issuer
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let assets = state.db.list_assets()?;
    let rows = assets
        .into_iter()
        .filter(|asset| issuer.as_ref().is_none_or(|issuer| &asset.issuer == issuer))
        .map(|asset| asset_response(&state.db, asset))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

/// One asset's registry record by ref — the canonical lookup.
async fn get_asset<P: Payload>(
    State(state): State<AppState<P>>,
    Path(asset_ref): Path<String>,
) -> Result<Json<AssetResponse>, ApiError> {
    let asset_ref = parse_ref(&asset_ref)?;
    let asset = state.db.get_asset(&asset_ref)?.ok_or(ApiError::NotFound)?;
    Ok(Json(asset_response(&state.db, asset)?))
}

/// Slug resolution — "is this name taken?" for a register form. The ref is
/// a pure function of `(issuer, asset_id)`, so this derives it and looks the
/// record up; 404 means the slug is free for that issuer, and the response
/// body carries the ref the registration would produce.
async fn get_asset_alias<P: Payload>(
    State(state): State<AppState<P>>,
    Path((issuer, asset_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let issuer = parse_address(&issuer)?;
    let asset_ref =
        AssetRef::derive(&issuer, &asset_id).map_err(|err| ApiError::BadRequest(err.to_string()))?;
    match state.db.get_asset(&asset_ref)? {
        Some(asset) => Ok(Json(asset_response(&state.db, asset)?).into_response()),
        None => Ok((StatusCode::NOT_FOUND, Json(serde_json::json!({ "ref": asset_ref }))).into_response()),
    }
}

/// One row of `GET /attestors` — a registered KYC provider.
#[derive(serde::Serialize)]
struct AttestorResponse {
    attestor: String,
    name: String,
    registered_at: u64,
}

/// Every attestor currently in the trust-spectrum registry.
async fn get_attestors<P: Payload>(
    State(state): State<AppState<P>>,
) -> Result<Json<Vec<AttestorResponse>>, ApiError> {
    Ok(Json(
        state
            .db
            .list_attestors()?
            .into_iter()
            .map(|(attestor, record)| AttestorResponse {
                attestor: attestor.to_string(),
                name: record.name,
                registered_at: record.registered_at,
            })
            .collect(),
    ))
}

/// One address's attestor registry record, if currently registered.
async fn get_attestor<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<AttestorResponse>, ApiError> {
    let address = parse_address(&address)?;
    let record = state.db.get_attestor_record(&address)?.ok_or(ApiError::NotFound)?;
    Ok(Json(AttestorResponse {
        attestor: address.to_string(),
        name: record.name,
        registered_at: record.registered_at,
    }))
}

#[derive(serde::Deserialize)]
struct ValidatorSetQuery {
    /// Historical height to answer for. Absent means the chain's tip.
    height: Option<u64>,
}

/// The validator set, by default as of the chain's tip — the same set
/// `xc_executor::accept_block` would check the next block's proposer against.
///
/// `?height=N` answers for a past height instead. The snapshots have always
/// been persisted (`validator_set:{height}`, read back by
/// `get_validator_set_at`, which `arxd/finality` already relies on to tally
/// votes against the set that was live at the voted height) — they simply had
/// no route. Exposing them is what lets an external indexer compute validator
/// uptime: turns proposed over turns *owed* needs the set at each historical
/// height, and the denominator was unobtainable while this only answered for
/// the tip.
/// Finality status, and — when nothing is finalizing — enough to tell why.
///
/// A bare "latest finalized height" would report `null` both for a chain that
/// is simply young and for one structurally unable to finalize at all, which
/// is the failure this endpoint exists to surface: a validator only votes if
/// it has registered a BLS key, and nothing requires one. A set can be
/// perfectly healthy for block production and never reach quorum, with no
/// symptom beyond a `warn!` per dropped vote. Reporting the set size, how many
/// of them can actually vote, and the quorum those numbers imply makes that
/// visible in one request.
async fn get_finality<P: Payload>(State(state): State<AppState<P>>) -> Result<Response, ApiError> {
    let tip_height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let validators = state.db.get_validator_set_at(tip_height)?;

    let mut voters = 0usize;
    let mut keyed: Vec<&Address> = Vec::new();
    for validator in validators.keys() {
        if state.db.get_bls_pubkey(validator)?.is_some() {
            voters += 1;
            keyed.push(validator);
        }
    }
    // Quorum is by voting power, so what matters is how much of it can
    // actually sign — a keyless whale can block finality on its own.
    let voting_power_with_bls_key = signed_power(&validators, keyed);

    let finalized_height = state.db.get_finalized_height()?;
    let record = match finalized_height {
        Some(height) => state.db.get_finality_record(height)?,
        None => None,
    };
    let final_watermark = state.db.get_final_watermark()?;

    Ok(Json(serde_json::json!({
        // null rather than absent: a client must be able to tell "nothing has
        // finalized yet" from "this node is too old to have the field".
        "finalized_height": finalized_height,
        "finalized_hash": record.as_ref().map(|r| r.block_hash),
        "signers": record.as_ref().map(|r| r.signers.clone()),
        "tip_height": tip_height,
        // How far behind the tip finality is running. Growing steadily means
        // votes are being produced but not reaching quorum.
        "blocks_behind_tip": finalized_height.map(|h| tip_height.saturating_sub(h)),
        // Irreversibility floor, as opposed to `finalized_height`'s highest
        // certificate: everything at or below this is contiguously certified
        // and no node will roll it back.
        "final_watermark": final_watermark,
        "validators": validators.len(),
        "validators_with_bls_key": voters,
        "total_voting_power": TOTAL_VOTING_POWER,
        "voting_power_with_bls_key": voting_power_with_bls_key,
        // Voting power a certificate needs, out of `total_voting_power`.
        "quorum": QUORUM_POWER,
        // The whole point: false means no amount of waiting will finalize
        // anything, because not enough of the set's power can even vote.
        "quorum_reachable": voting_power_with_bls_key >= QUORUM_POWER,
    }))
    .into_response())
}

async fn get_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Json<Vec<Address>>, ApiError> {
    let tip_height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;

    // Membership only, sorted — the shape Retracer's uptime view and the
    // proposer formula (`sorted(set)[height % len]`) consume. Weights are
    // on `/validators/power`.
    Ok(Json(state.db.validator_addresses_at(height)?))
}

/// `{address: voting_power}` for the set at `?height=` (default: tip) —
/// the units `GET /finality`'s `quorum` is measured in.
async fn get_validator_power<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ValidatorSetQuery>,
) -> Result<Json<BTreeMap<String, u32>>, ApiError> {
    let tip_height = state.db.get_tip_height()?.ok_or(ApiError::ServiceUnavailable)?;
    let height = resolve_height(query.height, tip_height)?;
    Ok(Json(
        state.db.get_validator_set_at(height)?.into_iter().map(|(a, p)| (a.to_string(), p.0)).collect(),
    ))
}

/// One validator's standing: its `ValidatorStatus` (Active / Pending /
/// Jailed / Leaving / Tombstoned — the state the epoch hook and the fault
/// paths already keep, previously unreachable over RPC), its voting power
/// in the tip set (0 when not in it), whether a BLS key is registered, and
/// its operator if any. 404 for an address that never staked to join.
async fn get_validator<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Response, ApiError> {
    let address = parse_address(&address)?;
    let status = state.db.get_validator_status(&address)?.ok_or(ApiError::NotFound)?;
    let tip = state.db.get_tip_height()?.unwrap_or(0);
    let voting_power =
        state.db.get_validator_set_at(tip)?.into_iter().find(|(a, _)| a == &address).map(|(_, p)| p.0).unwrap_or(0);
    let bls = state.db.get_bls_pubkey(&address)?;
    let operator = state.db.get_operator(&address)?;
    Ok(Json(serde_json::json!({
        "address": address,
        "status": status,
        "voting_power": voting_power,
        "bls_registered": bls.is_some(),
        "operator": operator,
    }))
    .into_response())
}

/// Every validator address currently authorizing `address` to submit
/// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey` on its behalf (see
/// `ActionPayload::AuthorizeOperator`) — drives a "your validators" listing
/// for a delegated-management client.
async fn get_operator_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<Address>>, ApiError> {
    let address = parse_address(&address)?;
    Ok(Json(state.db.get_validators_for_operator(&address)?))
}

/// Status of a submitted action: "pending" while it's still queued in the
/// mempool, "confirmed" once a block including it is on the chain, and
/// "dropped" with the executor's reason when this node drained it and
/// failed to apply it (bad nonce, insufficient balance…). The dropped
/// record is an in-memory ring on the mempool, so it survives until ~1k
/// later drops or a restart; after that the action is a 404 like one that
/// was never sent.
async fn get_action_status<P: Payload>(
    State(state): State<AppState<P>>,
    Path(signature): Path<String>,
) -> Result<Response, ApiError> {
    {
        let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if mempool.contains_signature(&signature) {
            return Ok(Json(serde_json::json!({ "status": "pending" })).into_response());
        }
        if let Some(reason) = mempool.dropped_reason(&signature) {
            return Ok(Json(serde_json::json!({ "status": "dropped", "reason": reason })).into_response());
        }
    }

    let height = state.db.get_action_block_height(&signature)?.ok_or(ApiError::NotFound)?;
    let block = state.db.get_block::<P>(height)?.ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("action index points at missing block {height} for {signature}"))
    })?;
    let action = block
        .actions
        .iter()
        .find(|action| action.signature.as_deref() == Some(signature.as_str()))
        .ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!(
                "action index points at block {height} but action {signature} isn't in it"
            ))
        })?;

    Ok(Json(serde_json::json!({
        "status": "confirmed",
        "height": height,
        "block_hash": block.hash(),
        "sender": action.sender,
        "nonce": action.nonce,
    }))
    .into_response())
}

#[derive(serde::Deserialize)]
struct BlockRangeQuery {
    from: u64,
    to: u64,
}

/// Bounded window of blocks. Heights are sequential with no gaps (single
/// proposer, no forks), so this is a per-height point-lookup loop capped at
/// `MAX_PAGE_SIZE`, not a scan.
/// Serializes a block with a `finalized` flag alongside its own fields.
///
/// Injected into the block's own JSON object rather than nesting the block
/// under a wrapper, so this stays additive: every existing consumer keeps
/// reading `height`, `hash`, `actions` exactly where they were, and clients
/// that don't know about `finalized` ignore it.
///
/// Checked per height rather than compared against a single watermark because
/// certificates are written as quorums complete, which is not necessarily in
/// height order — see `ArxiumDb::get_finalized_height`. A block below the
/// highest certified height is not automatically certified itself.
fn block_with_finality<P: Payload>(
    db: &ArxiumDb,
    block: &Block<P>,
) -> Result<serde_json::Value, StorageError> {
    let finalized = db.get_finality_record(block.height)?.is_some();
    let weight_used = db.get_block_weight(block.height)?;
    let mut value = serde_json::to_value(block).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("finalized".into(), serde_json::Value::Bool(finalized));
        // PoE `resources_used`: the metered weight this block carried.
        object.insert("weight_used".into(), serde_json::Value::from(weight_used));
    }
    Ok(value)
}

async fn get_blocks<P: Payload>(
    State(state): State<AppState<P>>,
    Query(range): Query<BlockRangeQuery>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    if range.from > range.to {
        return Err(ApiError::BadRequest("from must be <= to".to_string()));
    }
    // One finality lookup per block. The range is already capped, so this
    // is bounded; a single watermark comparison would be cheaper but wrong
    // for the reason `block_with_finality` documents.
    let blocks = state.db.get_block_range::<P>(range.from, range.to)?;
    let annotated =
        blocks.iter().map(|block| block_with_finality(&state.db, block)).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(annotated))
}

async fn get_block_by_height<P: Payload>(
    State(state): State<AppState<P>>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let block = state.db.get_block::<P>(height)?.ok_or(ApiError::NotFound)?;
    Ok(Json(block_with_finality(&state.db, &block)?))
}

async fn get_block_by_hash<P: Payload>(
    State(state): State<AppState<P>>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Case/prefix are normalized before the lookup, not compared as raw
    // strings, so `/blocks/AABBCC...` finds the same block as
    // `/blocks/aabbcc...`. A string that isn't even a valid 32-byte hash
    // can't name any block, same as one that doesn't match.
    let Ok(hash) = hash.parse::<Hash32>() else {
        return Err(ApiError::NotFound);
    };
    let height = state.db.get_block_height_by_hash(&hash)?.ok_or(ApiError::NotFound)?;
    let block = state.db.get_block::<P>(height)?.ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("block_hash index points at missing block {height} for {hash}"))
    })?;
    Ok(Json(block_with_finality(&state.db, &block)?))
}

/// Lists the filenames `xc_evidence::write_equivocation_artifact` /
/// `write_disagreement_artifact` have written to `evidence_dir` — each one
/// an `EvidenceArtifact` an outside party can fetch via `GET /evidence/{id}`
/// and check with `arx-verify`, no shell access to the node required.
async fn get_evidence_list<P: Payload>(State(state): State<AppState<P>>) -> Result<Json<Vec<String>>, ApiError> {
    let entries = match std::fs::read_dir(&state.evidence_dir) {
        Ok(entries) => entries,
        // No evidence directory yet just means no faults observed so far.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Json(Vec::new())),
        Err(err) => return Err(ApiError::internal(err)),
    };

    let mut ids: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .collect();
    ids.sort();
    Ok(Json(ids))
}

/// Serves one evidence artifact's raw JSON by filename, as listed by
/// `GET /evidence`. `id` is a filename, not a path — reject anything that
/// could escape `evidence_dir` rather than trusting the caller.
async fn get_evidence_by_id<P: Payload>(
    State(state): State<AppState<P>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(ApiError::BadRequest("invalid evidence id".to_string()));
    }
    let path = state.evidence_dir.join(&id);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(err) => Err(ApiError::internal(err)),
    }
}

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: String,
}

/// Single lookup endpoint so a client doesn't need to guess whether `q` is
/// a height, an address, or a block/action hash — tries each in turn.
async fn search<P: Payload>(
    State(state): State<AppState<P>>,
    Query(SearchQuery { q }): Query<SearchQuery>,
) -> Response {
    if let Ok(height) = q.parse::<u64>()
        && matches!(state.db.get_block::<P>(height), Ok(Some(_))) {
            return Json(serde_json::json!({ "kind": "block", "height": height }))
                .into_response();
        }

    if let Ok(address) = Address::parse(&q) {
        return Json(serde_json::json!({ "kind": "account", "address": address }))
            .into_response();
    }

    if let Ok(hash) = q.parse::<Hash32>()
        && let Ok(Some(height)) = state.db.get_block_height_by_hash(&hash) {
            return Json(serde_json::json!({ "kind": "block", "height": height })).into_response();
        }

    if let Ok(Some(height)) = state.db.get_action_block_height(&q) {
        return Json(serde_json::json!({ "kind": "action", "signature": q, "height": height }))
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
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
        assert!(limiter.allow(ip, false), "read budget must be independent of the write budget");
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
        let limits = Limits { rpc_rate_limit_writes: 2, ..Limits::default() };
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
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                for address in ["arx1aaaaaaaa", "arx1bbbbbbbb"] {
                    app.clone().oneshot(request(&format!("/accounts/{address}"))).await.unwrap();
                }
                // A 404 must not mint a label of its own either — the guard
                // wraps the fallback too.
                app.clone().oneshot(request("/no/such/route/arx1cccccccc")).await.unwrap();
            });
        });

        let rendered = handle.render();
        assert!(rendered.contains("path=\"/accounts/{address}\""), "{rendered}");
        assert!(rendered.contains(&format!("path=\"{UNMATCHED_PATH}\"")), "{rendered}");
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
            .layer(middleware::from_fn_with_state(state.clone(), admin_guard::<TestPayload>));
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
                .body(axum::body::Body::from(format!("{{\"output\": {:?}}}", output.display().to_string())))
                .unwrap()
        };

        assert_eq!(app.clone().oneshot(request(None)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            app.clone().oneshot(request(Some("Bearer rpc"))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "the shared rpc token must not open admin routes"
        );

        let response = app.clone().oneshot(request(Some("Bearer admin"))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["height"], 0);
        assert!(json["finalized_height"].is_null());

        let reopened = ArxiumDb::open(&output).unwrap();
        assert_eq!(reopened.get_tip_height().unwrap(), Some(0));
        drop(reopened);

        assert_eq!(
            app.oneshot(request(Some("Bearer admin"))).await.unwrap().status(),
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
        .await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["pubkey"], format!("0x{}", "ab".repeat(48)));
    }

    #[test]
    fn pairing_store_is_single_use_and_rejects_unknown_or_reused_nonces() {
        let store = PairingStore::new();
        let validator = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let operator = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();

        assert!(matches!(store.submit("no-such-nonce", operator.clone()), SubmitOutcome::NotFound));
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
            PollOutcome::Fulfilled { validator: v, operator: o } => {
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

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string())).await.into_response();
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

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
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
            .await.into_response();
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
            .await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = get_delegated_stake(
                State(state.clone()),
                Path((operator.to_string(), validator.to_string())),
            )
            .await.into_response();
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
            let resp = submit_action(State(state.clone()), Ok(Json(tampered))).await.into_response();
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
            let resp = submit_action(State(state.clone()), Ok(Json(stale))).await.into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            // Far-future nonce: can never execute until every nonce below it
            // does, and `purge_stale` never reclaims it — so it must not take
            // a mempool slot at all.
            let far_future = signed_action(&key, 5 + state.max_nonce_gap + 1);
            let resp = submit_action(State(state.clone()), Ok(Json(far_future))).await.into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(state.mempool.lock().unwrap().len(), 0);

            // The edge of the window is still admissible.
            let edge = signed_action(&key, 5 + state.max_nonce_gap);
            let resp = submit_action(State(state.clone()), Ok(Json(edge))).await.into_response();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            // Correctly signed, current nonce: must be accepted into the mempool.
            let valid = signed_action(&key, 5);
            let resp = submit_action(State(state.clone()), Ok(Json(valid))).await.into_response();
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
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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
            let index = state.db.asset_index_updates(&[alice_gold.clone(), bob_gold.clone()], &balances).unwrap();
            state.db.write_batches(&[&alice_gold, &bob_gold, &balances, &index]).unwrap();

            let resp = get_asset(State(state.clone()), Path(alice_gold.asset_ref.to_string())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            assert_eq!(body["ref"], alice_gold.asset_ref.to_string());
            assert_eq!(body["asset_id"], "gold");
            assert_eq!(body["symbol"], "GOLD");
            assert_eq!(body["issuer"], alice.to_string());
            assert_eq!(body["issuer_attested"], false);
            assert_eq!(body["holders"], 1);

            // The slug is not a route: a non-ref path segment is a 400.
            let resp = get_asset(State(state.clone()), Path("gold".into())).await.into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            let resp = get_assets(State(state.clone()), Query(AssetsQuery { issuer: Some(bob.to_string()) })).await.into_response();
            let body = json(resp).await;
            assert_eq!(body.as_array().unwrap().len(), 1);
            assert_eq!(body[0]["ref"], bob_gold.asset_ref.to_string());
            let resp = get_assets(State(state.clone()), Query(AssetsQuery { issuer: None })).await.into_response();
            assert_eq!(json(resp).await.as_array().unwrap().len(), 2);

            let resp = get_asset_alias(State(state.clone()), Path((bob.to_string(), "gold".into()))).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(json(resp).await["ref"], bob_gold.asset_ref.to_string());
            let resp = get_asset_alias(State(state.clone()), Path((bob.to_string(), "silver".into()))).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            assert_eq!(json(resp).await["ref"], AssetRef::derive(&bob, "silver").unwrap().to_string());

            let resp = get_account_asset_balance(State(state.clone()), Path((bob.to_string(), alice_gold.asset_ref.to_string()))).await.into_response();
            let body = json(resp).await;
            assert_eq!(body["balance"], 7);
            assert_eq!(body["issuer"], alice.to_string());
            let resp = get_account_assets(State(state.clone()), Path(bob.to_string())).await.into_response();
            let body = json(resp).await;
            let rows = body.as_array().unwrap();
            assert_eq!(rows.len(), 2);
            let bobs = rows.iter().find(|r| r["ref"] == bob_gold.asset_ref.to_string()).unwrap();
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
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
            let nobody = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
            let accounts = AccountUpdates(BTreeMap::from([(
                alice.clone(),
                xc_primitives::AccountEntry { balance: 42, ..Default::default() },
            )]));
            state.db.write_batch(&accounts).unwrap();
            let genesis = Block::<TestPayload> {
                state_root: state.db.compute_state_root(&[]).unwrap(),
                ..Block::genesis(0)
            };
            state.db.write_batch(&genesis).unwrap();

            for (who, expect_value) in [(&alice, Some(42u64)), (&nobody, None)] {
                let resp = get_account_proof(State(state.clone()), Path(who.to_string())).await.into_response();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = json(resp).await;
                assert_eq!(body["height"], 0);
                assert_eq!(body["state_root"], genesis.state_root);
                assert_eq!(body["block_hash"], genesis.hash().to_string());
                assert_eq!(body["value"]["balance"].as_u64(), expect_value);
                let proof: xc_artifact::StateProof = serde_json::from_value(body["proof"].clone()).unwrap();
                let root: [u8; 32] =
                    hex::decode(genesis.state_root.trim_start_matches("0x")).unwrap().try_into().unwrap();
                xc_artifact::verify_state_proof(root, &proof).expect("proof verifies against the named root");
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
            let balances = AssetBalanceUpdates(BTreeMap::from([((asset.asset_ref.clone(), holder.clone()), u128::MAX)]));
            let holder_states = HolderStateUpdates(BTreeMap::from([(
                (asset.asset_ref.clone(), holder.clone()),
                HolderState { frozen: false, frozen_amount: u128::MAX },
            )]));
            let index = state.db.asset_index_updates(std::slice::from_ref(&asset), &balances).unwrap();
            state.db.write_batches(&[&asset, &balances, &holder_states, &index]).unwrap();

            let resp = get_account_assets(State(state), Path(holder.to_string())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(text.contains(&format!("\"frozen_amount\":{}", u128::MAX)), "exact u128 JSON: {text}");
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

    fn block_with_action(height: u64, action: Action<TestPayload>) -> xc_primitives::Block<TestPayload> {
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
            .await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.as_array().unwrap().len(), 3);

            let resp = get_block_by_height(State(state.clone()), Path(1)).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_height(State(state.clone()), Path(99)).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let target_hash = state.db.get_block::<TestPayload>(1).unwrap().unwrap().hash();
            let resp = get_block_by_hash(State(state.clone()), Path(target_hash.to_string())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_hash(State(state.clone()), Path("0xnope".into())).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn evidence_list_and_fetch_serve_the_evidence_dir_and_reject_path_traversal() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();

            // No evidence directory yet just means no faults observed so far.
            let resp = get_evidence_list(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json.as_array().unwrap().is_empty());

            std::fs::create_dir_all(&state.evidence_dir).unwrap();
            std::fs::write(state.evidence_dir.join("fault-1.json"), b"{\"ok\":true}").unwrap();

            let resp = get_evidence_list(State(state.clone())).await.into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.as_array().unwrap(), &["fault-1.json"]);

            let resp = get_evidence_by_id(State(state.clone()), Path("fault-1.json".into())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"{\"ok\":true}");

            let resp = get_evidence_by_id(State(state.clone()), Path("no-such-file.json".into())).await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = get_evidence_by_id(State(state.clone()), Path("../secrets.json".into())).await.into_response();
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
            let resp = search(State(state.clone()), Query(SearchQuery { q: "1".into() })).await.into_response();
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
            .await.into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            // search by address
            let resp = search(
                State(state.clone()),
                Query(SearchQuery {
                    q: sender.to_string(),
                }),
            )
            .await.into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["kind"], "account");

            // search by action signature
            let resp = search(
                State(state.clone()),
                Query(SearchQuery { q: last_sig }),
            )
            .await.into_response();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["kind"], "action");

            // search miss
            let resp = search(
                State(state.clone()),
                Query(SearchQuery { q: "nonsense".into() }),
            )
            .await.into_response();
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
                .write_batch(&xc_storage::ValidatorSetSnapshot::equal_power(0, &[validator.clone()]))
                .unwrap();

            let resp = get_finality::<TestPayload>(State(state.clone())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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

            let resp = get_finality::<TestPayload>(State(state.clone())).await.into_response();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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

            let resp = get_block_by_height::<TestPayload>(State(state.clone()), Path(0)).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            assert_eq!(json["finalized"], false, "no certificate written yet");
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

            let resp = get_block_by_height::<TestPayload>(State(state.clone()), Path(0)).await.into_response();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["finalized"], true);
        });
    }
}
