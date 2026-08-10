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
/// balance/nonce, needed to sign the next action),
/// `GET /actions/{signature}` (pending/confirmed status of a submitted
/// action), and `GET /status` (chain name, tip height/hash). If `rpc_token`
/// is set, every request must carry a matching
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
                .route("/status", get(get_status))
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

/// Validates what can be checked without executing the action: signature,
/// and that its nonce isn't already stale against on-chain state. This is
/// deliberately not a full re-check of `execute_actions` — balance can
/// still change between now and this action's turn in a block, so
/// insufficient-balance is still only caught at production time. Rejecting
/// a bad signature or a replayed/stale nonce here means garbage never
/// occupies a mempool slot waiting to be dropped later.
async fn submit_action(
    State(state): State<AppState>,
    body: Result<Json<Action>, JsonRejection>,
) -> Response {
    let action = match body {
        Ok(Json(action)) => action,
        Err(err) => {
            warn!("rejected unparsable RPC action: {err}");
            return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
        }
    };
    let sender = action.sender.clone();

    if let Err(err) = action.verify_signature() {
        warn!("rejected action from {sender}: {err}");
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    let current_nonce = match state.db.get_account(&sender) {
        Ok(account) => account.map(|entry| entry.nonce).unwrap_or(0),
        Err(err) => {
            warn!("failed to look up account {sender} for nonce check: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if action.nonce < current_nonce {
        let msg = format!(
            "stale nonce for {sender}: action has {}, current on-chain nonce is {current_nonce}",
            action.nonce
        );
        warn!("rejected action from {sender}: {msg}");
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

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

/// Chain-wide health: name, tip height/hash. No per-account or per-action
/// state, so unlike other routes it can't 404 — an initialized node always
/// has at least the genesis block.
async fn get_status(State(state): State<AppState>) -> Response {
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

    let tip_hash = match state.db.get_block(tip_height) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use xc_primitives::{AccountEntry, ActionPayload, Snapshot};

    fn test_state() -> AppState {
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
        }
    }

    fn signed_action(key: &SigningKey, nonce: u64) -> Action {
        let sender = Address::from_pubkey_bytes(key.verifying_key().as_bytes()).unwrap();
        let to = Address::from_pubkey_bytes(&[9u8; 32]).unwrap();
        let mut action = Action {
            sender,
            nonce,
            signature: None,
            payload: ActionPayload::Transfer { to, amount: 1 },
        };
        let sig = key.sign(&action.signing_bytes());
        action.signature = Some(hex::encode(sig.to_bytes()));
        action
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
                        },
                    )]),
                    validators: BTreeMap::new(),
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
    fn status_reports_chain_name_and_tip_before_and_after_a_block() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = test_state();

            // No genesis written yet: nothing to report.
            let resp = get_status(State(state.clone())).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            let genesis = xc_primitives::Block::genesis(0);
            state
                .db
                .write_batch(&Snapshot {
                    height: 0,
                    chain_name: "test-chain".into(),
                    accounts: BTreeMap::new(),
                    validators: BTreeMap::new(),
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
}
