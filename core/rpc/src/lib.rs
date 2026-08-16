use anyhow::{Context, Result};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
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
use xc_mempool::{AdmissionError, Mempool, MempoolError, validate_action};
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
const RATE_LIMIT_MAX_REQUESTS: u32 = 60;
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
}

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
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Sweep stale entries once the map gets large rather than every call —
        // bounds worst-case memory without paying a scan on every request.
        if hits.len() > RATE_LIMIT_SWEEP_THRESHOLD {
            hits.retain(|_, (seen, _)| now.duration_since(*seen) <= RATE_LIMIT_WINDOW);
        }

        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) > RATE_LIMIT_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= RATE_LIMIT_MAX_REQUESTS
    }
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

    if !state.rate_limiter.allow(client_ip(&req, addr)) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    next.run(req).await
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
/// action), and `GET /status` (chain name, tip height/hash). If `rpc_token`
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
) -> Result<()> {
    let (ready_tx, ready_rx) = mpsc::channel::<std::io::Result<()>>();
    let state = AppState {
        mempool,
        db,
        rpc_token: rpc_token.map(Arc::new),
        rate_limiter: Arc::new(RateLimiter::new()),
        gossip_tx,
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
                .route("/actions", post(submit_action::<P>))
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .route("/accounts/{address}", get(get_account::<P>))
                .route("/actions/{signature}", get(get_action_status::<P>))
                .route("/blocks", get(get_blocks::<P>))
                .route("/blocks/{height}", get(get_block_by_height::<P>))
                .route("/blocks/by-hash/{hash}", get(get_block_by_hash::<P>))
                .route("/search", get(search::<P>))
                .route("/status", get(get_status::<P>))
                .with_state(state.clone())
                .layer(middleware::from_fn_with_state(state, guard::<P>))
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
/// stale-nonce check — see its doc comment) before it ever touches the
/// mempool, same as gossip-received actions do in `network`.
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
