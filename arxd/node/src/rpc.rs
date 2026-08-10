use anyhow::{Context, Result};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use xc_mempool::{Mempool, MempoolError};
use xc_primitives::{Action, Address};
use xc_storage::ArxiumDb;

// ponytail: fixed cap on a single JSON action body; make configurable if a
// payload type ever legitimately needs more than this.
const MAX_BODY_BYTES: usize = 64 * 1024;

// ponytail: fixed window, single-node in-memory; move to a shared store
// (redis, etc.) if this ever runs behind more than one RPC instance.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_REQUESTS: u32 = 60;

#[derive(Clone)]
struct AppState {
    mempool: Arc<Mutex<Mempool>>,
    db: ArxiumDb,
    rpc_token: Option<Arc<String>>,
    rate_limiter: Arc<RateLimiter>,
}

// ponytail: HashMap entries are never evicted for IPs that stop sending
// requests; fine for a devnet, add a sweep/LRU if this runs long-lived and
// public.
struct RateLimiter {
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let mut hits = self.hits.lock().unwrap();
        let now = Instant::now();
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) > RATE_LIMIT_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= RATE_LIMIT_MAX_REQUESTS
    }
}

async fn guard(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
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
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    if !state.rate_limiter.allow(addr.ip()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    next.run(req).await
}

/// Runs the RPC server on its own tokio runtime, on a dedicated thread, so
/// the rest of the node (bootstrap, block production loop) stays plain sync.
/// Serves `POST /actions` (submit a JSON-encoded `Action`, queued into
/// `mempool` for the next block), `GET /accounts/{address}` (current
/// balance/nonce, needed to sign the next action), and
/// `GET /actions/{signature}` (pending/confirmed status of a submitted
/// action). If `rpc_token` is set, every request must carry a matching
/// `Authorization: Bearer` header. Blocks the caller until the listener is
/// bound (or fails to bind), same as a sync server would, so startup
/// failures surface immediately instead of on first request.
pub fn spawn_http_ingest(
    mempool: Arc<Mutex<Mempool>>,
    db: ArxiumDb,
    bind_addr: String,
    port: u16,
    rpc_token: Option<String>,
) -> Result<()> {
    let (ready_tx, ready_rx) = mpsc::channel::<std::io::Result<()>>();
    let state = AppState {
        mempool,
        db,
        rpc_token: rpc_token.map(Arc::new),
        rate_limiter: Arc::new(RateLimiter::new()),
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
            let app = Router::new()
                .route("/actions", post(submit_action))
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .route("/accounts/{address}", get(get_account))
                .route("/actions/{signature}", get(get_action_status))
                .with_state(state.clone())
                .layer(middleware::from_fn_with_state(state, guard));

            let listener = match tokio::net::TcpListener::bind((bind_addr.as_str(), port)).await {
                Ok(listener) => listener,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            info!(
                "RPC listening on {bind_addr}:{port} (POST /actions, GET /accounts/:address, GET /actions/:signature)"
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

async fn submit_action(
    State(state): State<AppState>,
    body: Result<Json<Action>, JsonRejection>,
) -> Response {
    match body {
        Ok(Json(action)) => {
            let sender = action.sender.clone();
            match state.mempool.lock().unwrap().push(action) {
                Ok(()) => {
                    info!("queued action from {sender} via RPC");
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
        Err(err) => {
            warn!("rejected unparsable RPC action: {err}");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn get_account(State(state): State<AppState>, Path(address): Path<String>) -> Response {
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

/// Status of a submitted action: "pending" while it's still queued in the
/// mempool, "confirmed" once a block including it is on the chain. An
/// action that was dropped by the executor (bad signature, stale nonce)
/// looks the same as one that was never submitted — 404 — since neither is
/// persisted anywhere; that's a real gap if a client needs to distinguish
/// "never sent" from "sent then rejected", not addressed here.
async fn get_action_status(
    State(state): State<AppState>,
    Path(signature): Path<String>,
) -> Response {
    if state.mempool.lock().unwrap().contains_signature(&signature) {
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

    let block = match state.db.get_block(height) {
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
