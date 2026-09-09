//! The HTTP control-plane gateway.
//!
//! A small JSON API in front of the account store so a browser can create a
//! tenant and receive an API key. The account service speaks a TCP framed
//! binary protocol a browser cannot; this bridges to it by reusing
//! [`AccountStore`] directly (decision record 0046).
//!
//! v1 exposes tenant signup plus API-key management (decision record 0048). Key
//! management re-authenticates the tenant with its email/username + password on
//! every call, since there is no tenant session yet:
//!
//! - `POST /v1/tenants` — body `{ "username", "email", "password" }`; on success
//!   `201 { "tenant_id", "api_key" }`. The API key is returned **once** — the
//!   store keeps only its hash — so the caller must save it.
//! - `POST /v1/tenants/keys/create` — `{ "email", "password", "label"? }`;
//!   `201 { "api_key", "key_prefix" }`. Mints an additional key (rotation).
//! - `POST /v1/tenants/keys/list` — `{ "email", "password" }`;
//!   `200 { "keys": [ { "prefix", "label", "created_at" } ] }`. Never the secret.
//! - `POST /v1/tenants/keys/revoke` — `{ "email", "password", "prefix" }`;
//!   `200 { "revoked": bool }`. The revoked key stops resolving at once.
//!
//! Bad credentials return `401 { "error": "invalid_credentials" }`.
//!
//! Outside `v1`, and unauthenticated: `GET /.well-known/tacenta` is the
//! service document (decision 0090), saying where this deployment's
//! four services are and how to trust them. See [`ServiceDocument`].
//!
//! `GET /v1/ws/{directory|relay|accounts|provisioning}` upgrades to a
//! WebSocket carrying that service's framing as binary messages: the gateway
//! dials the service's TCP port (over the trust the document names) and
//! pipes bytes both ways, so a browser, which cannot open a TCP socket,
//! speaks the unchanged protocol (decision 0090). Authentication is the
//! service's own, inside the bytes; the gateway adds none and reads none.
//! The dial happens before the upgrade, so a service that is down answers
//! `502` rather than a socket that closes at once, and the paths answer
//! `404` when the document offers no carriage. One residual: the services
//! see every carried connection as coming from the gateway, so the
//! directory's per-source registration throttle (decision 0079) would pool
//! all carriage clients into one bucket; the gateway therefore throttles
//! directory upgrades per client IP itself, with a ceiling loose enough for
//! reconnects and tight enough to bound a single abuser.
//!
//! Signup is throttled **per client IP** (the source address the account TCP
//! service never sees), which is the natural home for the signup-throttling the
//! threat model records as a gap. The gateway trusts the left-most
//! `X-Forwarded-For` entry set by a front proxy, falling back to a single shared
//! bucket; deploy it behind a TLS-terminating proxy that sets that header.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tacenta_accounts::{AccountStore, SignupError, StoreError, TenantId};
pub use tacenta_discovery::{ServiceDocument, Tls};
use tacenta_transport::ClientTls;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

mod ratelimit;
use ratelimit::IpRateLimiter;

/// Shared gateway state: the account store, the per-IP signup throttle, and
/// the service document this deployment publishes.
#[derive(Clone)]
pub struct GatewayState {
    store: Arc<AccountStore>,
    limiter: Arc<Mutex<IpRateLimiter>>,
    /// Directory upgrades per client IP; see the module documentation.
    directory_limiter: Arc<Mutex<IpRateLimiter>>,
    service: Arc<ServiceDocument>,
    upstream: Arc<Upstream>,
}

/// Directory upgrades allowed per client IP per hour over the carriage: a
/// client opens one per sign-in and one per reconnect, so this bounds an
/// abuser well above what a flapping network costs a real user.
const DIRECTORY_UPGRADES_PER_HOUR: usize = 120;

/// Where the gateway itself dials the four services for the WebSocket
/// carriage, and how it trusts them: the document's addresses and trust,
/// with the host optionally replaced by an internal name that the document's
/// public name resolves to from outside.
pub struct Upstream {
    directory: String,
    relay: String,
    accounts: String,
    provisioning: String,
    trust: Option<(String, ClientTls)>,
}

impl Upstream {
    /// The upstream a document implies, dialling `host` instead of the
    /// document's hosts when given.
    pub fn from_document(doc: &ServiceDocument, host: Option<&str>) -> Result<Upstream, String> {
        let at = |entry: &str| match host {
            Some(h) => {
                let port = entry.rsplit(':').next().unwrap_or("");
                let h = if h.contains(':') {
                    format!("[{h}]")
                } else {
                    h.to_owned()
                };
                format!("{h}:{port}")
            }
            None => entry.to_owned(),
        };
        let trust = tacenta_transport::trust_for(&doc.tls, &doc.server_name)
            .map_err(|e| format!("the document's private trust anchors: {e}"))?;
        Ok(Upstream {
            directory: at(&doc.directory),
            relay: at(&doc.relay),
            accounts: at(&doc.accounts),
            provisioning: at(&doc.provisioning),
            trust,
        })
    }

    fn address(&self, service: &str) -> Option<&str> {
        Some(match service {
            "directory" => &self.directory,
            "relay" => &self.relay,
            "accounts" => &self.accounts,
            "provisioning" => &self.provisioning,
            _ => return None,
        })
    }
}

impl GatewayState {
    /// Build state over an account store, with the default signup throttle and
    /// a service document pointing at the four services on loopback without
    /// TLS: the shape of a development server run with `cargo run -p
    /// tacenta-server`. A deployment uses [`with_service`](Self::with_service).
    pub fn new(store: Arc<AccountStore>) -> GatewayState {
        GatewayState::with_service(store, ServiceDocument::local("127.0.0.1"))
            .expect("the loopback document carries no trust anchors to fail on")
    }

    /// Build state over an account store, publishing `service` as this
    /// deployment's service document and dialling the services at the
    /// addresses it names. Fails only when the document's private trust
    /// anchors do not parse.
    pub fn with_service(
        store: Arc<AccountStore>,
        service: ServiceDocument,
    ) -> Result<GatewayState, String> {
        GatewayState::with_upstream(store, service, None)
    }

    /// [`with_service`](Self::with_service), dialling the services at
    /// `upstream_host` (an internal name) rather than the document's hosts.
    pub fn with_upstream(
        store: Arc<AccountStore>,
        service: ServiceDocument,
        upstream_host: Option<&str>,
    ) -> Result<GatewayState, String> {
        let upstream = Upstream::from_document(&service, upstream_host)?;
        Ok(GatewayState {
            store,
            limiter: Arc::new(Mutex::new(IpRateLimiter::default())),
            directory_limiter: Arc::new(Mutex::new(IpRateLimiter::with_limit(
                DIRECTORY_UPGRADES_PER_HOUR,
            ))),
            service: Arc::new(service),
            upstream: Arc::new(upstream),
        })
    }
}

// The service document itself is `tacenta_discovery::ServiceDocument`, the
// one definition the client reads too; this crate only serves it. Which
// document a deployment publishes is the binary's decision (`main.rs`), from
// the same `SITE_DOMAIN` the rest of the stack is configured with.

/// `GET /v1/ws/{service}`: dial the service, then upgrade and pipe bytes.
async fn ws_service(
    State(state): State<GatewayState>,
    Path(service): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(addr) = state.upstream.address(&service).map(str::to_owned) else {
        return error(StatusCode::NOT_FOUND, "unknown_service");
    };
    if state.service.ws.is_none() {
        // Not offered: an operator who withholds the carriage from the
        // document has closed it, not merely hidden it.
        return error(StatusCode::NOT_FOUND, "no_websocket_carriage");
    }
    if service == "directory" {
        let ip = client_ip(&headers);
        let over = state
            .directory_limiter
            .lock()
            .expect("gateway directory limiter poisoned")
            .check_and_record(&ip);
        if over {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
    }
    // Dial first: a service that is down is a 502 the client and the
    // access log can both read, not a socket that opens and closes.
    let upstream = match dial(&addr, state.upstream.trust.as_ref()).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("tacenta-gateway: websocket carriage: cannot reach {service} at {addr}: {e}");
            return error(StatusCode::BAD_GATEWAY, "service_unreachable");
        }
    };
    ws.on_upgrade(move |socket| async move {
        // A dropped peer ends the socket; there is no one to report to but
        // the client, who sees the close.
        let _ = relay_bytes(socket, upstream).await;
    })
}

/// A dialled service, plain or under TLS.
enum Dialled {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Dialled {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialled::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Dialled::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Dialled {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Dialled::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Dialled::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialled::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Dialled::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialled::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Dialled::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Dial `addr` under `trust`.
async fn dial(addr: &str, trust: Option<&(String, ClientTls)>) -> std::io::Result<Dialled> {
    let tcp = TcpStream::connect(addr).await?;
    Ok(match trust {
        Some((name, tls)) => Dialled::Tls(Box::new(tls.wrap_tcp(name, tcp).await?)),
        None => Dialled::Plain(tcp),
    })
}

/// Binary messages become bytes on the upstream; upstream bytes become
/// binary messages. When the client closes, the upstream's write side is
/// shut so the service sees end of stream and answers what it still has;
/// the socket closes when the upstream ends. When the upstream ends first,
/// the socket is closed with a close frame the client can read.
async fn relay_bytes<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: WebSocket,
    upstream: S,
) -> std::io::Result<()> {
    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let (mut ws_tx, mut ws_rx) = socket.split();
    let to_upstream = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if up_write.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = up_write.shutdown().await;
    });
    let mut buf = bytes::BytesMut::with_capacity(16 * 1024);
    let outcome = loop {
        buf.reserve(16 * 1024);
        match up_read.read_buf(&mut buf).await {
            Ok(0) => break Ok(()),
            Ok(_) => {
                let chunk = buf.split().freeze();
                if let Err(e) = ws_tx.send(Message::Binary(chunk)).await {
                    break Err(std::io::Error::other(e));
                }
            }
            Err(e) => break Err(e),
        }
    };
    let _ = ws_tx.close().await;
    to_upstream.abort();
    outcome
}

/// `GET /.well-known/tacenta`: the service document. Public and cacheable; it
/// carries nothing a client could not learn by connecting.
async fn service(State(state): State<GatewayState>) -> Response {
    (
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        Json((*state.service).clone()),
    )
        .into_response()
}

/// The `POST /v1/tenants` request body.
#[derive(Debug, Deserialize)]
pub struct CreateTenant {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// The success body: the tenant's id and its one-time API key.
#[derive(Debug, Serialize)]
pub struct TenantCreated {
    pub tenant_id: String,
    pub api_key: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    /// A coarse, machine-readable reason. Mirrors the account protocol's
    /// `SignupReason`; never distinguishes more than the store admits.
    error: &'static str,
}

fn error(status: StatusCode, reason: &'static str) -> Response {
    (status, Json(ErrorBody { error: reason })).into_response()
}

/// Build the gateway router over `state`, allowing CORS from `origins` (exact
/// origins, never a wildcard — the browser sends credentials-free JSON but the
/// origin allow-list keeps the API off arbitrary pages).
pub fn app(state: GatewayState, origins: &[String]) -> Router {
    use axum::http::{HeaderValue, Method};
    use tower_http::cors::CorsLayer;

    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(allowed)
        // GET for the service document, which a browser-side client will read.
        .allow_methods([Method::POST, Method::GET])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    Router::new()
        .route(tacenta_discovery::WELL_KNOWN_PATH, get(service))
        .route("/v1/ws/{service}", get(ws_service))
        .route("/v1/tenants", post(create_tenant))
        .route("/v1/tenants/keys/create", post(create_key))
        .route("/v1/tenants/keys/list", post(list_keys))
        .route("/v1/tenants/keys/revoke", post(revoke_key))
        .layer(cors)
        .with_state(state)
}

/// Record a request against the per-IP throttle; `true` means over the ceiling
/// and the caller should return `429`. Shared by signup and key management —
/// both are sensitive control-plane operations from an IP.
fn throttled(state: &GatewayState, headers: &HeaderMap) -> bool {
    let ip = client_ip(headers);
    let mut limiter = state.limiter.lock().expect("gateway limiter poisoned");
    limiter.check_and_record(&ip)
}

/// The address to throttle on: the rightmost `X-Forwarded-For` entry, the
/// one the nearest proxy appended, or a single shared bucket if the header
/// is absent (no proxy in front; a single bucket is the safe, if blunt,
/// default).
///
/// **`x-forwarded-for` is written by the client, and only its rightmost
/// element is trusted.** A front proxy *appends* the peer it saw rather than
/// replacing the header, so a request arriving with `x-forwarded-for:
/// 10.0.0.1` reaches the gateway as `10.0.0.1, <real client>` and the first
/// element is whatever the caller chose. Trusting it would have two
/// consequences, both reachable without authenticating on a public endpoint:
/// the throttle could be bypassed entirely by varying the header per request,
/// and every distinct value would add a permanent entry to the limiter's map.
///
/// **The rightmost element is the trustworthy one**, because it is the one the
/// nearest proxy added; everything to its left is hearsay from further out.
/// Taking the last entry means an attacker can only prepend, which changes
/// nothing.
///
/// A caller that cannot supply the header at all still gets throttled together
/// under `shared`, which is the conservative direction: it over-groups rather
/// than under-groups.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "shared".to_owned())
}

/// Emit one signup event to stderr. **Aggregate signal only** — never an
/// email, IP, username, key, or any other field from the request. The whole
/// line is `event` + `outcome`, so counting signup outcomes is a grep over
/// the log without the instrumentation ever touching a user's data. The
/// browser sends nothing to anyone; the server counts its own outcomes.
/// Counts are the process's stderr history, not a
/// persisted metric — durable only as far as the log is.
fn funnel(event: &str, outcome: &str) {
    eprintln!("funnel event={event} outcome={outcome}");
}

/// The coarse outcome label for a signup result — the single source of truth for
/// both the client-facing reason and the stderr event, so the two cannot drift.
fn signup_outcome(e: &SignupError) -> &'static str {
    match e {
        SignupError::UsernameTaken => "username_taken",
        SignupError::EmailTaken => "email_taken",
        SignupError::InvalidUsername => "invalid_username",
        SignupError::InvalidEmail => "invalid_email",
        SignupError::WeakPassword => "weak_password",
        SignupError::UnknownTenant => "server_error",
    }
}

async fn create_tenant(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(body): Json<CreateTenant>,
) -> Response {
    if throttled(&state, &headers) {
        funnel("signup", "rate_limited");
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }

    match state
        .store
        .sign_up_tenant(&body.username, &body.email, &body.password)
        .await
    {
        Ok((tenant, api_key)) => {
            funnel("signup", "created");
            (
                StatusCode::CREATED,
                Json(TenantCreated {
                    tenant_id: tenant.id.as_str().to_owned(),
                    api_key: api_key.as_str().to_owned(),
                }),
            )
                .into_response()
        }
        Err(StoreError::Signup(e)) => {
            funnel("signup", signup_outcome(&e));
            signup_error(e)
        }
        Err(_) => {
            funnel("signup", "server_error");
            error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// Map a signup failure to an HTTP status + coarse reason. `409` for a taken
/// identifier, `422` for invalid input; `UnknownTenant` cannot occur here
/// (tenant signup has no parent tenant). The reason string is `signup_outcome`,
/// shared with the stderr event.
fn signup_error(e: SignupError) -> Response {
    let status = match e {
        SignupError::UsernameTaken | SignupError::EmailTaken => StatusCode::CONFLICT,
        SignupError::InvalidUsername | SignupError::InvalidEmail | SignupError::WeakPassword => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        SignupError::UnknownTenant => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error(status, signup_outcome(&e))
}

// --- API-key management ------------------------------------------------------

/// Credentials shared by every key-management request (there is no tenant
/// session yet, so each call re-authenticates).
#[derive(Debug, Deserialize)]
struct KeyAuth {
    email: String,
    password: String,
}

/// `POST /v1/tenants/keys/create` body.
#[derive(Debug, Deserialize)]
struct CreateKey {
    email: String,
    password: String,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /v1/tenants/keys/revoke` body.
#[derive(Debug, Deserialize)]
struct RevokeKey {
    email: String,
    password: String,
    prefix: String,
}

#[derive(Debug, Serialize)]
struct KeyCreated {
    api_key: String,
    key_prefix: String,
}

#[derive(Debug, Serialize)]
struct KeyList {
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Serialize)]
struct KeyEntry {
    prefix: String,
    label: Option<String>,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct KeyRevoked {
    revoked: bool,
}

/// Resolve the tenant from email/username + password, or return the error
/// response to send: `401` for bad credentials (coarse — never distinguishes no
/// such tenant from wrong password), `500` for a backend failure.
async fn authenticate(
    state: &GatewayState,
    email: &str,
    password: &str,
) -> Result<TenantId, Box<Response>> {
    match state.store.authenticate_tenant(email, password).await {
        Ok(tenant) => Ok(tenant),
        Err(StoreError::Auth(_)) => Err(Box::new(error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        ))),
        Err(_) => Err(Box::new(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ))),
    }
}

async fn create_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(body): Json<CreateKey>,
) -> Response {
    if throttled(&state, &headers) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let tenant = match authenticate(&state, &body.email, &body.password).await {
        Ok(tenant) => tenant,
        Err(resp) => return *resp,
    };
    let label = body.label.filter(|l| !l.trim().is_empty());
    match state.store.create_api_key(&tenant, label).await {
        Ok(key) => {
            // Activation: a signed-up tenant is now minting a key to use, the
            // step past signup that matters most.
            funnel("activation", "key_created");
            (
                StatusCode::CREATED,
                Json(KeyCreated {
                    key_prefix: key.prefix(),
                    api_key: key.as_str().to_owned(),
                }),
            )
                .into_response()
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

async fn list_keys(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(body): Json<KeyAuth>,
) -> Response {
    if throttled(&state, &headers) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let tenant = match authenticate(&state, &body.email, &body.password).await {
        Ok(tenant) => tenant,
        Err(resp) => return *resp,
    };
    match state.store.list_api_keys(&tenant).await {
        Ok(keys) => (
            StatusCode::OK,
            Json(KeyList {
                keys: keys
                    .into_iter()
                    .map(|k| KeyEntry {
                        prefix: k.prefix,
                        label: k.label,
                        created_at: k.created_at,
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

async fn revoke_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(body): Json<RevokeKey>,
) -> Response {
    if throttled(&state, &headers) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let tenant = match authenticate(&state, &body.email, &body.password).await {
        Ok(tenant) => tenant,
        Err(resp) => return *resp,
    };
    match state.store.revoke_api_key(&tenant, &body.prefix).await {
        Ok(revoked) => (StatusCode::OK, Json(KeyRevoked { revoked })).into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _; // oneshot

    fn state() -> GatewayState {
        GatewayState::new(Arc::new(AccountStore::memory(
            tacenta_accounts::Accounts::new(),
        )))
    }

    async fn post_json(
        app: Router,
        path: &str,
        xff: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", xff)
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn post_tenants(app: Router, xff: &str, body: &str) -> (StatusCode, serde_json::Value) {
        post_json(app, "/v1/tenants", xff, body).await
    }

    #[tokio::test]
    async fn the_service_document_is_served_at_the_well_known_path() {
        let st = GatewayState::with_service(
            Arc::new(AccountStore::memory(tacenta_accounts::Accounts::new())),
            ServiceDocument::hosted("tacenta.example"),
        )
        .unwrap();
        let res = app(st.clone(), &[])
            .oneshot(
                Request::builder()
                    .uri("/.well-known/tacenta")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["cache-control"], "public, max-age=300");
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let doc: ServiceDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc, ServiceDocument::hosted("tacenta.example"));
        assert_eq!(doc.accounts, "tacenta.example:4722");
        assert_eq!(doc.tls, Tls::WebPki);

        // No alias: the well-known path is the one the decision names.
        let res = app(st, &[])
            .oneshot(
                Request::builder()
                    .uri("/v1/service")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_upstream_follows_the_document_with_an_internal_host() {
        let doc = ServiceDocument::hosted("tacenta.example");
        let up = Upstream::from_document(&doc, Some("server")).unwrap();
        assert_eq!(up.address("relay"), Some("server:4721"));
        assert_eq!(up.address("provisioning"), Some("server:4723"));
        assert_eq!(up.address("mailbox"), None);
        assert_eq!(up.directory, "server:4720");
        assert_eq!(
            up.trust.as_ref().map(|(n, _)| n.as_str()),
            Some("tacenta.example")
        );
        let up = Upstream::from_document(&ServiceDocument::local("127.0.0.1"), None).unwrap();
        assert_eq!(up.address("accounts"), Some("127.0.0.1:4722"));
        assert!(up.trust.is_none());
        let up = Upstream::from_document(&doc, Some("::1")).unwrap();
        assert_eq!(up.address("directory"), Some("[::1]:4720"));
    }

    #[test]
    fn the_default_state_publishes_a_plaintext_loopback_server() {
        let st = state();
        assert_eq!(*st.service, ServiceDocument::local("127.0.0.1"));
        assert_eq!(st.service.tls, Tls::None);
        assert_eq!(st.service.directory, "127.0.0.1:4720");
    }

    #[tokio::test]
    async fn creating_a_tenant_returns_an_id_and_key() {
        let app = app(state(), &["http://localhost:4321".to_string()]);
        let (status, json) = post_tenants(
            app,
            "192.0.2.4",
            r#"{"username":"acme","email":"admin@acme.example","password":"correct horse"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(json["tenant_id"].as_str().unwrap().starts_with("ten_"));
        assert!(json["api_key"].as_str().unwrap().starts_with("tct_"));
    }

    #[tokio::test]
    async fn a_taken_username_is_a_conflict() {
        let st = state();
        let app1 = app(st.clone(), &[]);
        let _ = post_tenants(
            app1,
            "192.0.2.4",
            r#"{"username":"acme","email":"a@acme.example","password":"correct horse"}"#,
        )
        .await;
        // Same username, different IP so the rate limit does not mask it.
        let app2 = app(st, &[]);
        let (status, json) = post_tenants(
            app2,
            "192.0.2.8",
            r#"{"username":"acme","email":"other@acme.example","password":"correct horse"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"], "username_taken");
    }

    #[tokio::test]
    async fn invalid_input_is_unprocessable() {
        let app = app(state(), &[]);
        let (status, json) = post_tenants(
            app,
            "192.0.2.4",
            r#"{"username":"acme","email":"not-an-email","password":"correct horse"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"], "invalid_email");
    }

    #[tokio::test]
    async fn one_ip_is_throttled_after_the_ceiling() {
        let st = state();
        // The default ceiling is small; exhaust it from one IP with invalid
        // bodies (cheap — they never reach argon2) and confirm the next is 429.
        let ip = "198.51.100.9";
        let mut last = StatusCode::OK;
        for _ in 0..10 {
            let app = app(st.clone(), &[]);
            let (status, _) = post_tenants(
                app,
                ip,
                r#"{"username":"ab","email":"x","password":"short"}"#,
            )
            .await;
            last = status;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
        // A different IP is unaffected.
        let app = app(st, &[]);
        let (status, _) = post_tenants(
            app,
            "198.51.100.8",
            r#"{"username":"ab","email":"x","password":"short"}"#,
        )
        .await;
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    // Each request uses a distinct IP so the shared per-IP throttle never masks
    // an assertion. Credentials are the tenant's email + password.
    #[tokio::test]
    async fn a_tenant_creates_lists_and_revokes_keys() {
        let st = state();
        let creds = r#""email":"admin@acme.example","password":"correct horse""#;
        let (s, _) = post_tenants(
            app(st.clone(), &[]),
            "10.0.0.1",
            r#"{"username":"acme","email":"admin@acme.example","password":"correct horse"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);

        // Mint a second key.
        let (s, created) = post_json(
            app(st.clone(), &[]),
            "/v1/tenants/keys/create",
            "10.0.0.2",
            &format!("{{{creds},\"label\":\"ci\"}}"),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let key = created["api_key"].as_str().unwrap();
        let prefix = created["key_prefix"].as_str().unwrap();
        assert!(key.starts_with("tct_"));
        assert!(key.starts_with(prefix), "the key carries its prefix");
        let prefix = prefix.to_owned();

        // Both keys are listed (signup key + the new one), never the secret.
        let (s, listed) = post_json(
            app(st.clone(), &[]),
            "/v1/tenants/keys/list",
            "10.0.0.3",
            &format!("{{{creds}}}"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(listed["keys"].as_array().unwrap().len(), 2);
        assert!(listed.to_string().contains(&prefix));
        assert!(
            !listed.to_string().contains(key),
            "list never carries the secret"
        );

        // Revoke the new key by prefix.
        let (s, revoked) = post_json(
            app(st.clone(), &[]),
            "/v1/tenants/keys/revoke",
            "10.0.0.4",
            &format!("{{{creds},\"prefix\":\"{prefix}\"}}"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(revoked["revoked"], true);

        // One key remains.
        let (s, listed) = post_json(
            app(st, &[]),
            "/v1/tenants/keys/list",
            "10.0.0.5",
            &format!("{{{creds}}}"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn key_management_rejects_a_wrong_password() {
        let st = state();
        let _ = post_tenants(
            app(st.clone(), &[]),
            "10.1.0.1",
            r#"{"username":"acme","email":"admin@acme.example","password":"correct horse"}"#,
        )
        .await;
        let (s, json) = post_json(
            app(st, &[]),
            "/v1/tenants/keys/list",
            "10.1.0.2",
            r#"{"email":"admin@acme.example","password":"wrong"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "invalid_credentials");
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        h
    }

    /// **The bypass a first-element read would allow.** A front proxy appends
    /// the peer it saw, so a client that sends its own `x-forwarded-for` puts a
    /// value of its choosing to the *left* of the real one. Reading the first
    /// element would let a caller pick a fresh throttle bucket per request.
    #[test]
    fn a_client_supplied_prefix_cannot_choose_the_bucket() {
        let spoofed = client_ip(&headers("192.0.2.4, 203.0.113.7"));
        let also_spoofed = client_ip(&headers("192.0.2.9, 203.0.113.7"));
        assert_eq!(
            spoofed, also_spoofed,
            "varying the prepended value must not change the bucket"
        );
        assert_eq!(
            spoofed, "203.0.113.7",
            "the proxy-appended value is the one"
        );
    }

    #[test]
    fn a_single_element_is_used_as_is() {
        assert_eq!(client_ip(&headers("203.0.113.7")), "203.0.113.7");
    }

    /// No header at all groups callers together rather than giving each its own
    /// bucket: over-grouping is the conservative direction for a throttle.
    #[test]
    fn a_missing_header_falls_back_to_a_shared_bucket() {
        assert_eq!(client_ip(&HeaderMap::new()), "shared");
    }
}
