// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! `POST /pairing`, `POST /pairing/{nonce}`, `GET /pairing/{nonce}` — lets an
//! `arxd pair` process authorize an operator wallet without the validator's
//! signing key ever leaving the node it runs on.

use super::*;

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

pub(super) enum SubmitOutcome {
    Ok(Address),
    NotFound,
    AlreadyFulfilled,
}

pub(super) struct PairingStore {
    sessions: Mutex<HashMap<String, PairingSession>>,
}

impl PairingStore {
    pub(super) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn start(&self, validator: Address) -> String {
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

    pub(super) fn submit(&self, nonce: &str, operator: Address) -> SubmitOutcome {
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
    pub(super) fn poll(&self, nonce: &str) -> PollOutcome {
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

pub(super) enum PollOutcome {
    Fulfilled {
        validator: Address,
        operator: Address,
    },
    Pending,
    NotFound,
}

#[derive(serde::Deserialize)]
pub(super) struct StartPairingRequest {
    validator: Address,
}

#[derive(Serialize)]
pub(super) struct StartPairingResponse {
    nonce: String,
}

/// Called by an `arxd pair` process (never by the app) to register a
/// pairing session for `validator` — the node it runs on holds that
/// validator's signing key and never hands it over; this just gives the app
/// a nonce to fill in with the operator address it wants authorized. Behind
/// the same bearer-token guard as `/actions`.
pub(super) async fn start_pairing<P: Payload>(
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
pub(super) struct SubmitPairingRequest {
    operator: Address,
}

/// Called by the app once it's scanned an `arxd pair` QR, naming the
/// address it wants authorized as that validator's operator. Doesn't
/// authorize anything by itself — `arxd pair` still has to poll this up
/// (`poll_pairing`) and self-sign the actual `AuthorizeOperator` action.
pub(super) async fn submit_pairing<P: Payload>(
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
pub(super) struct PollPairingResponse {
    validator: Address,
    operator: Address,
}

/// Polled by `arxd pair` while it waits for `submit_pairing`. Consumes the
/// session on the first successful read — see `PairingStore::poll`.
pub(super) async fn poll_pairing<P: Payload>(
    State(state): State<AppState<P>>,
    Path(nonce): Path<String>,
) -> Response {
    match state.pairing.poll(&nonce) {
        PollOutcome::Fulfilled {
            validator,
            operator,
        } => Json(PollPairingResponse {
            validator,
            operator,
        })
        .into_response(),
        PollOutcome::Pending => StatusCode::ACCEPTED.into_response(),
        PollOutcome::NotFound => {
            (StatusCode::NOT_FOUND, "unknown or expired pairing session").into_response()
        }
    }
}
