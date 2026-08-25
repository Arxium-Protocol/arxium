// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use xc_mempool::{AdmissionError, Mempool, MempoolError, PayloadPrecheck, validate_action};
use xc_primitives::{Action, Address};
use xc_storage::ArxiumDb;

/// Bound every chain's payload type must satisfy to be served over this RPC:
/// JSON (de)serializable for the wire, `Clone` because `AppState` is cloned
/// per request, `Send + Sync + 'static` to live inside the shared axum state.
pub trait Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<P: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> Payload for P {}

// ponytail: fixed cap on a single JSON action body; make configurable if a
// payload type ever legitimately needs more than this.
const MAX_BODY_BYTES: usize = 64 * 1024;

// ponytail: fixed window, single-node in-memory; move to a shared store
// (redis, etc.) if this ever runs behind more than one RPC instance.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
// Writes (state-mutating: POST /actions, POST /pairing) keep the original
// tight budget — this is the one that actually needs to bound spam/DoS
// risk against the mempool and chain state.
const RATE_LIMIT_MAX_WRITE_REQUESTS: u32 = 60;
// Reads (GET /accounts/*, /blocks/*, etc.) are cheap lookups against
// already-committed state, not a mempool/consensus risk, so they get a much
// higher ceiling. Load-testing this RPC (scripts/load-test) surfaced the
// bug a single shared budget causes: a client's own status-check polling
// right after a submission burst would get starved by its own writes,
// making confirmed-on-chain actions look "still pending" indefinitely.
const RATE_LIMIT_MAX_READ_REQUESTS: u32 = 600;
// Sweep stale per-IP entries once the map crosses this size, bounding worst-
// case memory instead of growing forever for a public/long-lived instance.
const RATE_LIMIT_SWEEP_THRESHOLD: usize = 10_000;

#[derive(Clone)]
struct AppState<P: Payload> {
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    rpc_token: Option<Arc<String>>,
    rate_limiter: Arc<RateLimiter>,
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
}

struct RateLimiter {
    // Keyed by (ip, is_write) so a client's write budget and read budget
    // are tracked — and exhausted — independently. Same map/sweep shape as
    // the single-budget version, just keyed one level deeper.
    hits: Mutex<HashMap<(IpAddr, bool), (Instant, u32)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr, is_write: bool) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Sweep stale entries once the map gets large rather than every call —
        // bounds worst-case memory without paying a scan on every request.
        if hits.len() > RATE_LIMIT_SWEEP_THRESHOLD {
            hits.retain(|_, (seen, _)| now.duration_since(*seen) <= RATE_LIMIT_WINDOW);
        }

        let max = if is_write { RATE_LIMIT_MAX_WRITE_REQUESTS } else { RATE_LIMIT_MAX_READ_REQUESTS };
        let entry = hits.entry((ip, is_write)).or_insert((now, 0));
        if now.duration_since(entry.0) > RATE_LIMIT_WINDOW {
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

/// The client IP to key rate limiting on. `ConnectInfo` alone is wrong once
/// this sits behind the reverse proxy the README already calls for in
/// production (TLS termination) — every real client would collapse into the
/// proxy's one IP and share a single limit. `X-Forwarded-For`'s first entry
/// wins when present, `X-Real-IP` next — verified empirically against a real
/// Caddy `reverse_proxy` (the documented deployment, see `Caddyfile.example`)
/// rather than assumed: Caddy doesn't append to a client-supplied
/// `X-Forwarded-For`, it overwrites it outright with its own observed remote
/// address, so there's never more than one entry to pick between when Caddy
/// is the immediate hop — a forged value from the actual client never
/// survives the proxy. `.next()` on the split is just reading that one
/// value; it isn't load-bearing leftmost-vs-rightmost logic. (A different
/// proxy, or a chain of more than one, could behave differently — recheck if
/// the deployment ever changes from a single Caddy hop.)
///
/// Only trusted from a loopback peer, though — the documented deployment is
/// the proxy running on the same host and forwarding to a loopback-bound RPC
/// (`rpc_bind` defaults to `127.0.0.1`). Trusting the header from *any* peer
/// would mean a direct connection (a stray `--rpc-bind 0.0.0.0` before the
/// proxy's wired up, a misconfigured deploy) could set a fresh
/// `X-Forwarded-For` on every request and the rate limiter would never
/// trigger — silently, no log line. A non-loopback peer always gets its own
/// real `addr`, spoofable header or not.
fn client_ip(req: &Request, addr: SocketAddr) -> IpAddr {
    if !addr.ip().is_loopback() {
        return addr.ip();
    }
    let header_ip = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .and_then(|v| v.parse::<IpAddr>().ok())
    };
    header_ip("x-forwarded-for")
        .or_else(|| header_ip("x-real-ip"))
        .unwrap_or(addr.ip())
}

async fn guard<P: Payload>(
    State(state): State<AppState<P>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // Path only (never the query string — addresses/signatures/heights can
    // appear there and would blow up the metric's cardinality), captured
    // before `req` moves into `next.run`.
    let path = req.uri().path().to_string();
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

    if !state.rate_limiter.allow(client_ip(&req, addr), is_write) {
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
/// meant to be internet-facing — see `docker-compose.prod.yml` / `Caddyfile.prod`,
/// which don't route it through the public TLS proxy).
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
pub fn spawn_http_ingest<P: Payload>(
    mempool: Arc<Mutex<Mempool<P>>>,
    db: ArxiumDb,
    bind_addr: String,
    port: u16,
    rpc_token: Option<String>,
    gossip_tx: Option<tokio::sync::mpsc::UnboundedSender<Action<P>>>,
    metrics_handle: PrometheusHandle,
    payload_precheck: Option<PayloadPrecheck<P>>,
    min_stake: Option<u128>,
    action_fee: Option<u128>,
) -> Result<()> {
    let (ready_tx, ready_rx) = mpsc::channel::<std::io::Result<()>>();
    let state = AppState {
        mempool,
        db,
        rpc_token: rpc_token.map(Arc::new),
        rate_limiter: Arc::new(RateLimiter::new()),
        gossip_tx,
        metrics_handle,
        payload_precheck,
        pairing: Arc::new(PairingStore::new()),
        min_stake,
        action_fee,
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
            // never routed through the public TLS proxy in production (see
            // Caddyfile.prod) since it's only meant for an internal scraper
            // on the same docker network.
            let guarded = Router::new()
                .route("/actions", post(submit_action::<P>))
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .route("/accounts/{address}", get(get_account::<P>))
                .route("/accounts/{address}/stake", get(get_account_stake::<P>))
                .route("/accounts/{address}/bls-key", get(get_account_bls_key::<P>))
                .route("/validators", get(get_validators::<P>))
                .route("/operators/{address}/validators", get(get_operator_validators::<P>))
                .route(
                    "/stake/{master}/{validator}",
                    get(get_delegated_stake::<P>),
                )
                .route("/actions/{signature}", get(get_action_status::<P>))
                .route("/blocks", get(get_blocks::<P>))
                .route("/blocks/{height}", get(get_block_by_height::<P>))
                .route("/blocks/by-hash/{hash}", get(get_block_by_hash::<P>))
                .route("/search", get(search::<P>))
                .route("/status", get(get_status::<P>))
                .route("/min-stake", get(get_min_stake::<P>))
                .route("/action-fee", get(get_action_fee::<P>))
                .route("/pairing", post(start_pairing::<P>))
                .route(
                    "/pairing/{nonce}",
                    post(submit_pairing::<P>).get(poll_pairing::<P>),
                )
                .with_state(state.clone())
                .layer(middleware::from_fn_with_state(state.clone(), guard::<P>));

            let app = Router::new()
                .route("/metrics", get(get_metrics::<P>))
                .with_state(state)
                .merge(guarded)
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

    match validate_action(&state.db, &action) {
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

    if let Some(precheck) = &state.payload_precheck {
        if let Err(err) = precheck(&action, &state.db) {
            warn!("rejected action from {sender}: {err}");
            return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
        }
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
        Err(err @ MempoolError::Full) => {
            warn!("rejected action from {sender}: {err}");
            (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response()
        }
        Err(err @ MempoolError::Duplicate { .. }) => {
            warn!("rejected action from {sender}: {err}");
            (StatusCode::CONFLICT, err.to_string()).into_response()
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
async fn get_status<P: Payload>(State(state): State<AppState<P>>) -> Response {
    let chain_name = match state.db.get_chain_name() {
        Ok(Some(name)) => name,
        Ok(None) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(err) => {
            warn!("failed to read chain name: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tip_height = match state.db.get_tip_height() {
        Ok(Some(height)) => height,
        Ok(None) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(err) => {
            warn!("failed to read tip height: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tip_hash = match state.db.get_block::<P>(tip_height) {
        Ok(Some(block)) => block.hash(),
        Ok(None) => {
            warn!("tip height {tip_height} recorded but block is missing");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(err) => {
            warn!("failed to load tip block {tip_height}: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(serde_json::json!({
        "chain_name": chain_name,
        "tip_height": tip_height,
        "tip_hash": tip_hash,
    }))
    .into_response()
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
async fn get_action_fee<P: Payload>(State(state): State<AppState<P>>) -> Response {
    match state.action_fee {
        Some(action_fee) => Json(serde_json::json!({ "action_fee": action_fee })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_account<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Response {
    let address = match Address::parse(&address) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match state.db.get_account(&address) {
        Ok(Some(account)) => Json(account).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_account_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Response {
    let address = match Address::parse(&address) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match state.db.get_stake_allocation(&address, &address) {
        Ok(Some(allocation)) => Json(allocation).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// A delegated stake allocation: `master` need not equal `validator` (unlike
/// `GET /accounts/{address}/stake`, the self-stake case) — this is how an
/// operator/app looks up how much it has staked on a validator's behalf.
async fn get_delegated_stake<P: Payload>(
    State(state): State<AppState<P>>,
    Path((master, validator)): Path<(String, String)>,
) -> Response {
    let master = match Address::parse(&master) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let validator = match Address::parse(&validator) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match state.db.get_stake_allocation(&master, &validator) {
        Ok(Some(allocation)) => Json(allocation).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Whether `address` has a BLS key registered for finality precommit voting
/// (`ActionPayload::RegisterBlsKey`) — a validator without one can be in the
/// validator set but its votes are silently dropped by `arxd/finality`.
async fn get_account_bls_key<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Response {
    let address = match Address::parse(&address) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match state.db.get_bls_pubkey(&address) {
        Ok(Some(pubkey)) => Json(serde_json::json!({ "pubkey": pubkey })).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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
async fn get_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Query(query): Query<ValidatorSetQuery>,
) -> Response {
    let tip_height = match state.db.get_tip_height() {
        Ok(Some(height)) => height,
        Ok(None) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // A height above the tip is a caller mistake worth naming: answering with
    // the tip's set would look like data rather than a misunderstanding.
    let height = match query.height {
        Some(requested) if requested > tip_height => {
            return (
                StatusCode::BAD_REQUEST,
                format!("height {requested} is above the chain tip {tip_height}"),
            )
                .into_response();
        }
        Some(requested) => requested,
        None => tip_height,
    };

    match state.db.get_validator_set_at(height) {
        Ok(validators) => Json(validators).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Every validator address currently authorizing `address` to submit
/// `JoinValidator`/`LeaveValidator`/`RegisterBlsKey` on its behalf (see
/// `ActionPayload::AuthorizeOperator`) — drives a "your validators" listing
/// for a delegated-management client.
async fn get_operator_validators<P: Payload>(
    State(state): State<AppState<P>>,
    Path(address): Path<String>,
) -> Response {
    let address = match Address::parse(&address) {
        Ok(address) => address,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match state.db.get_validators_for_operator(&address) {
        Ok(validators) => Json(validators).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Status of a submitted action: "pending" while it's still queued in the
/// mempool, "confirmed" once a block including it is on the chain. An
/// action that was dropped by the executor (bad signature, stale nonce)
/// looks the same as one that was never submitted — 404 — since neither is
/// persisted anywhere; that's a real gap if a client needs to distinguish
/// "never sent" from "sent then rejected", not addressed here.
async fn get_action_status<P: Payload>(
    State(state): State<AppState<P>>,
    Path(signature): Path<String>,
) -> Response {
    if state
        .mempool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_signature(&signature)
    {
        return Json(serde_json::json!({ "status": "pending" })).into_response();
    }

    let height = match state.db.get_action_block_height(&signature) {
        Ok(Some(height)) => height,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            warn!("failed to look up action {signature}: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let block = match state.db.get_block::<P>(height) {
        Ok(Some(block)) => block,
        Ok(None) => {
            warn!("action index points at missing block {height} for {signature}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(err) => {
            warn!("failed to load block {height} for {signature}: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(action) = block
        .actions
        .iter()
        .find(|action| action.signature.as_deref() == Some(signature.as_str()))
    else {
        warn!("action index points at block {height} but action {signature} isn't in it");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    Json(serde_json::json!({
        "status": "confirmed",
        "height": height,
        "block_hash": block.hash(),
        "sender": action.sender,
        "nonce": action.nonce,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct BlockRangeQuery {
    from: u64,
    to: u64,
}

/// Bounded window of blocks. Heights are sequential with no gaps (single
/// proposer, no forks), so this is a per-height point-lookup loop capped at
/// `MAX_PAGE_SIZE`, not a scan.
async fn get_blocks<P: Payload>(
    State(state): State<AppState<P>>,
    Query(range): Query<BlockRangeQuery>,
) -> Response {
    if range.from > range.to {
        return (StatusCode::BAD_REQUEST, "from must be <= to").into_response();
    }
    match state.db.get_block_range::<P>(range.from, range.to) {
        Ok(blocks) => Json(blocks).into_response(),
        Err(err) => {
            warn!("failed to load block range {}..={}: {err}", range.from, range.to);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_block_by_height<P: Payload>(
    State(state): State<AppState<P>>,
    Path(height): Path<u64>,
) -> Response {
    match state.db.get_block::<P>(height) {
        Ok(Some(block)) => Json(block).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            warn!("failed to load block {height}: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_block_by_hash<P: Payload>(
    State(state): State<AppState<P>>,
    Path(hash): Path<String>,
) -> Response {
    let height = match state.db.get_block_height_by_hash(&hash) {
        Ok(Some(height)) => height,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            warn!("failed to look up block hash {hash}: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match state.db.get_block::<P>(height) {
        Ok(Some(block)) => Json(block).into_response(),
        Ok(None) => {
            warn!("block_hash index points at missing block {height} for {hash}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            warn!("failed to load block {height} for hash {hash}: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
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
    if let Ok(height) = q.parse::<u64>() {
        if matches!(state.db.get_block::<P>(height), Ok(Some(_))) {
            return Json(serde_json::json!({ "kind": "block", "height": height }))
                .into_response();
        }
    }

    if let Ok(address) = Address::parse(&q) {
        return Json(serde_json::json!({ "kind": "account", "address": address }))
            .into_response();
    }

    if let Ok(Some(height)) = state.db.get_block_height_by_hash(&q) {
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
    use super::{IpAddr, RATE_LIMIT_MAX_READ_REQUESTS, RATE_LIMIT_MAX_WRITE_REQUESTS, RateLimiter};

    #[test]
    fn write_budget_exhausting_does_not_affect_reads() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..RATE_LIMIT_MAX_WRITE_REQUESTS {
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
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..RATE_LIMIT_MAX_READ_REQUESTS {
            assert!(limiter.allow(ip, false));
        }
        assert!(!limiter.allow(ip, false));
        assert!(RATE_LIMIT_MAX_READ_REQUESTS > RATE_LIMIT_MAX_WRITE_REQUESTS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, Snapshot};

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
            rate_limiter: Arc::new(RateLimiter::new()),
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

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string())).await;
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

            let resp = get_account_stake(State(state.clone()), Path(alice.to_string())).await;
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
            .await;
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
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = get_delegated_stake(
                State(state.clone()),
                Path((operator.to_string(), validator.to_string())),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["active_amount"], 2_500);
        });
    }

    #[test]
    fn client_ip_trusts_forwarded_header_only_from_a_loopback_peer() {
        let real_attacker: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let spoofed = "198.51.100.7";

        let req = Request::builder()
            .header("x-forwarded-for", spoofed)
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            client_ip(&req, real_attacker),
            real_attacker.ip(),
            "a direct, non-loopback peer must never have its header trusted"
        );

        let req = Request::builder()
            .header("x-forwarded-for", spoofed)
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            client_ip(&req, proxy),
            spoofed.parse::<IpAddr>().unwrap(),
            "the local reverse proxy's forwarded header must still be honored"
        );
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
            let resp = submit_action(State(state.clone()), Ok(Json(tampered))).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            // Sender is already at on-chain nonce 5 — nonce 0 is a stale replay.
            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    chain_name: "test".into(),
                    accounts: BTreeMap::from([(
                        sender.clone(),
                        AccountEntry {
                            balance: 1000,
                            nonce: 5,
                            identity_hash: None,
                            zk_identity_verified: false,
                        },
                    )]),
                    validators: BTreeMap::new(),
                    boot_nodes: Vec::new(),
                })
                .unwrap();
            let stale = signed_action(&key, 0);
            let resp = submit_action(State(state.clone()), Ok(Json(stale))).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

            // Correctly signed, current nonce: must be accepted into the mempool.
            let valid = signed_action(&key, 5);
            let resp = submit_action(State(state.clone()), Ok(Json(valid))).await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            assert_eq!(state.mempool.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn min_stake_reports_404_when_unset_and_the_value_when_set() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();
            let resp = get_min_stake(State(state.clone())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let mut state = state;
            state.min_stake = Some(1_000);
            let resp = get_min_stake(State(state)).await;
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
            let resp = get_action_fee(State(state.clone())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let mut state = state;
            state.action_fee = Some(10);
            let resp = get_action_fee(State(state)).await;
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
            let resp = get_status(State(state.clone())).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            let genesis: xc_primitives::Block<TestPayload> = xc_primitives::Block::genesis(0);
            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    chain_name: "test-chain".into(),
                    accounts: BTreeMap::new(),
                    validators: BTreeMap::new(),
                    boot_nodes: Vec::new(),
                })
                .unwrap();
            state.db.write_batch(&genesis).unwrap();

            let resp = get_status(State(state.clone())).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["chain_name"], "test-chain");
            assert_eq!(json["tip_height"], 0);
            assert_eq!(json["tip_hash"], genesis.hash());
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
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.as_array().unwrap().len(), 3);

            let resp = get_block_by_height(State(state.clone()), Path(1)).await;
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_height(State(state.clone()), Path(99)).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let target_hash = state.db.get_block::<TestPayload>(1).unwrap().unwrap().hash();
            let resp = get_block_by_hash(State(state.clone()), Path(target_hash)).await;
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = get_block_by_hash(State(state.clone()), Path("0xnope".into())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
            let resp = search(State(state.clone()), Query(SearchQuery { q: "1".into() })).await;
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
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            // search by address
            let resp = search(
                State(state.clone()),
                Query(SearchQuery {
                    q: sender.to_string(),
                }),
            )
            .await;
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
            .await;
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
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }
}
