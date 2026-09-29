//! Foreign-language bindings for the Tacenta client, via UniFFI.
//!
//! This exposes the [`tacenta_client`] facade to Swift and Kotlin: the tenant
//! handle [`Tenant`] (`connect` / `signUp` / `signIn`, decision record 0090)
//! and the [`Client`] it hands out (`find` / `send` / `receive`). Every call
//! that touches the network or the client's state is `async`: Swift sees
//! `async throws` methods and Kotlin `suspend fun`s. Each call spawns its
//! work on the SDK's own runtime and awaits the task, so the work runs on
//! the SDK's threads rather than on whichever thread the app awaits from,
//! and a call the app cancels detaches from a task that still runs to
//! completion: a socket round trip is never torn mid-response, and a batch
//! `receive` was waiting for is kept for the next call rather than lost.
//! The `Config`/`AccountConfig` constructors on `Client` are the address
//! layer under the handle, kept for callers that know their addresses.
//!
//! The handle is `Tenant` here rather than `Tacenta`, the Rust and TypeScript
//! name, because the Swift module is itself `Tacenta` and a type named like
//! its module shadows it, which makes `Tacenta.Client` unwritable in an app
//! that has its own `Client` (decision 0028's no-stuttering rule, applied to
//! a module boundary). Kotlin follows for parity between the two FFI heads.
//!
//! Naming follows the same rule as the Rust facade — no stuttering: the
//! object is `Client`, its methods are verbs (`send`, `receive`), and the
//! data types are plain nouns (`Config`, `Address`, `Message`).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::FutureExt;
use futures_util::future::Shared;
use tokio::sync::Mutex;

use tacenta_client::{
    AccountConfig as CoreAccountConfig, ClientTls, Config as CoreConfig, DefaultClient as Core,
    DeviceAddr, SecureStore as CoreSecureStore, SecureStoreError as CoreSecureStoreError,
    Tacenta as CoreTacenta,
};

uniffi::setup_scaffolding!();

/// Where to reach a Tacenta server, and who to connect as. Addresses are
/// `host:port` strings. This is the pre-account path — register directly under
/// a raw handle; for the account flow use [`AccountConfig`] with `Client.signIn`.
#[derive(uniffi::Record)]
pub struct Config {
    pub directory: String,
    pub relay: String,
    pub user: String,
    pub device: u8,
}

/// Where to reach a server's account endpoints, plus the credentials to sign
/// in with. Addresses are `host:port` strings. Used by the account flow
/// (`Client.signIn`), which signs in and provisions this device under the
/// account's handle (e.g. `acme/alice`).
#[derive(uniffi::Record)]
pub struct AccountConfig {
    pub directory: String,
    pub relay: String,
    pub accounts: String,
    pub provisioning: String,
    pub identifier: String,
    pub device: u8,
}

/// A resolved contact: another user's addressable handle, from `Client.find`.
#[derive(uniffi::Record)]
pub struct Contact {
    pub address: Address,
}

/// A device's routing address.
#[derive(uniffi::Record, Clone)]
pub struct Address {
    pub user: String,
    pub device: u32,
}

/// What the sign-in found: whether the sessions a restored state
/// carried are in use, or were discarded because the state was older than
/// one already seen. Read it with `Client.restoreOutcome` after any sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RestoreOutcome {
    /// No sessions were restored: a fresh identity, or an identity alone.
    Fresh,
    /// The state's sessions resumed as they were.
    Resumed,
    /// The state was a rollback: its sessions were discarded and the
    /// identity kept, so conversations re-establish on next contact. Show
    /// it to the user; keep the blob.
    SessionsDiscarded,
}

impl From<tacenta_client::RestoreOutcome> for RestoreOutcome {
    fn from(o: tacenta_client::RestoreOutcome) -> RestoreOutcome {
        use tacenta_client::RestoreOutcome as R;
        match o {
            R::Fresh => RestoreOutcome::Fresh,
            R::Resumed => RestoreOutcome::Resumed,
            // Non-exhaustive upstream: a value this crate does not know
            // yet is reported as the cautious one.
            R::SessionsDiscarded | _ => RestoreOutcome::SessionsDiscarded,
        }
    }
}

/// A decrypted inbound message and the device that sent it.
#[derive(Clone, uniffi::Record)]
pub struct Message {
    pub from: Address,
    pub plaintext: Vec<u8>,
}

/// Anything that can go wrong, as one case per kind an app can branch on:
/// the same kinds as every other head (decision 0090). Swift sees an enum
/// with a `reason` on each case; Kotlin a sealed exception class with one
/// subclass per kind. A case may be added, so switch with a default.
#[derive(Debug, Clone, uniffi::Error)]
pub enum ClientError {
    // Named `reason` rather than `message`: UniFFI maps an error enum to a
    // Kotlin exception, where a `message` field collides with
    // `Throwable.message` and the generated bindings do not compile. And no
    // case ends in `Error`: UniFFI's Kotlin renames such a case to
    // `...Exception`, which would break parity with the other heads.
    /// The network or the transport failed; retry later.
    Network { reason: String },
    /// The service document could not be fetched or read.
    Discovery { reason: String },
    /// The API key selects no tenant.
    UnknownTenant { reason: String },
    /// The username is already taken in this tenant.
    UsernameTaken { reason: String },
    /// The username is not one the server accepts.
    InvalidUsername { reason: String },
    /// The password is too weak.
    WeakPassword { reason: String },
    /// A sign-up was refused for another reason: registration is closed
    /// or the handle is reserved.
    SignUpRefused { reason: String },
    /// The credentials were refused, or the session expired. Coarse by
    /// design.
    SignInRefused { reason: String },
    /// The address is bound to a different device identity (trust on first
    /// use): resume from the saved state, or use another device number.
    IdentityMismatch { reason: String },
    /// The address is not registered.
    NotFound { reason: String },
    /// The server asked for a slower pace: too many failed sign-ins, or the
    /// recipient's queue is full. Back off and retry.
    RateLimited { reason: String },
    /// The server could not process the request; nothing was applied.
    ServerFailure { reason: String },
    /// The persisted state was refused: altered, older than the last send,
    /// or its secure-storage key is wrong. Whatever else a `SecureStore`
    /// implementation raises surfaces as this case, with its reason. Do not
    /// delete the blob.
    State { reason: String },
    /// The platform's secure store could not be reached: a Keychain before
    /// first unlock, a Keystore that needs the user. Nothing was refused;
    /// retry after unlock and keep the blob. A `SecureStore` implementation
    /// throws this case for exactly that, and the client passes it through.
    StoreUnavailable { reason: String },
    /// The caller's own input was wrong: a malformed address or config, a
    /// message over the size limit.
    InvalidArgument { reason: String },
    /// A protocol or cryptographic failure, or a bug: worth reporting.
    Internal { reason: String },
}

impl ClientError {
    fn reason(&self) -> &str {
        match self {
            ClientError::Network { reason }
            | ClientError::Discovery { reason }
            | ClientError::UnknownTenant { reason }
            | ClientError::UsernameTaken { reason }
            | ClientError::InvalidUsername { reason }
            | ClientError::WeakPassword { reason }
            | ClientError::SignUpRefused { reason }
            | ClientError::SignInRefused { reason }
            | ClientError::IdentityMismatch { reason }
            | ClientError::NotFound { reason }
            | ClientError::RateLimited { reason }
            | ClientError::ServerFailure { reason }
            | ClientError::State { reason }
            | ClientError::StoreUnavailable { reason }
            | ClientError::InvalidArgument { reason }
            | ClientError::Internal { reason } => reason,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl From<tacenta_client::Error> for ClientError {
    fn from(e: tacenta_client::Error) -> ClientError {
        use tacenta_client::ErrorKind as K;
        let reason = e.to_string();
        match e.kind() {
            K::Network => ClientError::Network { reason },
            K::Discovery => ClientError::Discovery { reason },
            K::UnknownTenant => ClientError::UnknownTenant { reason },
            K::UsernameTaken => ClientError::UsernameTaken { reason },
            K::InvalidUsername => ClientError::InvalidUsername { reason },
            K::WeakPassword => ClientError::WeakPassword { reason },
            K::SignUpRefused => ClientError::SignUpRefused { reason },
            K::SignInRefused => ClientError::SignInRefused { reason },
            K::IdentityMismatch => ClientError::IdentityMismatch { reason },
            K::NotFound => ClientError::NotFound { reason },
            K::RateLimited => ClientError::RateLimited { reason },
            K::ServerFailure => ClientError::ServerFailure { reason },
            K::State => ClientError::State { reason },
            K::StoreUnavailable => ClientError::StoreUnavailable { reason },
            K::InvalidArgument => ClientError::InvalidArgument { reason },
            // ErrorKind is non-exhaustive: a kind this crate does not know
            // yet is still an error, reported as a bug until it is mapped.
            K::Internal | _ => ClientError::Internal { reason },
        }
    }
}

/// A foreign `SecureStore` that raised something other than a
/// `ClientError` (a Kotlin `GeneralSecurityException`, say). Without this,
/// UniFFI would panic in the Rust frame and the app would not get a
/// catchable error at all.
impl From<uniffi::UnexpectedUniFFICallbackError> for ClientError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> ClientError {
        ClientError::State {
            reason: format!("secure storage raised an unexpected error: {}", e.reason),
        }
    }
}

/// The caller's own input was wrong: an address or a config that does not
/// parse.
fn invalid(reason: impl Into<String>) -> ClientError {
    ClientError::InvalidArgument {
        reason: reason.into(),
    }
}

/// Platform secure storage that holds the wrapping key for **sealed** state
/// (decision 0078, anchor B). Implemented on the foreign side — iOS/macOS
/// Keychain, Android Keystore — so the key lives where an attacker who can
/// rewrite the state file cannot reach it. That separation is the whole of what
/// sealing is worth: without it, an attacker who rewrites the blob rewrites the
/// key too and the authenticator proves nothing.
///
/// The implementation must return the **same 32-byte key across restarts** for a
/// given install (a changed key makes every restore look like tampering) and
/// must keep it unreadable to a file-rewriter. It is called on the SDK's own
/// threads, from inside a `send`, a `receive` or a restore, so it must not
/// touch the UI, wait on the app's threads, or call back into any `Tenant`
/// or `Client` method; do the storage work and return. See
/// `bindings/swift` and `bindings/android` for a Keychain and a Keystore
/// implementation.
#[uniffi::export(with_foreign)]
pub trait SecureStore: Send + Sync {
    /// Return the 32-byte wrapping key, creating and persisting it on first use.
    /// Raise an error if secure storage is unavailable — the caller must then
    /// use the unsealed path, which makes no rollback claim, rather than fall
    /// back to an unprotected key. A store that exists but cannot be reached
    /// yet (a Keychain before first unlock, a Keystore that needs the user)
    /// throws `StoreUnavailable`, which the client passes through as that
    /// kind, so the app retries after the unlock; anything else is `State`.
    fn wrap_key(&self) -> Result<Vec<u8>, ClientError>;

    /// Read the highest rollback counter this store has committed (0 if never).
    /// Read-only; used on restore to detect a same-generation rollback. Must be
    /// rollback-resistant to a file-rewriter (kept in secure storage) and must
    /// survive restarts.
    fn rollback_counter(&self) -> Result<u64, ClientError>;

    /// Atomically increment and persist the rollback counter, returning the new
    /// value. Never decreases. Called on **every `send` and every
    /// ratchet-advancing `receive`** (one advance each), not on export;
    /// `exportStateSealed` binds the current value. Because it tracks ratchet
    /// advances, a restore of any state older than the latest send presents a
    /// lower counter and is caught. Committing here is a per-message secure-storage
    /// write, so keep it fast.
    fn bump_rollback_counter(&self) -> Result<u64, ClientError>;
}

/// Adapts a foreign [`SecureStore`] to the core client's
/// [`tacenta_client::SecureStore`], validating that the foreign side returned a
/// 32-byte key.
struct FfiKeyStore(Arc<dyn SecureStore>);

/// What the foreign store raised, as the core distinguishes it: a store
/// that is not reachable keeps its own kind.
fn store_error(e: ClientError) -> CoreSecureStoreError {
    match e {
        ClientError::StoreUnavailable { reason } => CoreSecureStoreError::Unavailable(reason),
        other => CoreSecureStoreError::Backend(other.to_string()),
    }
}

impl CoreSecureStore for FfiKeyStore {
    fn wrap_key(&self) -> Result<[u8; 32], CoreSecureStoreError> {
        // The foreign store may block (a Keychain prompt, a Keystore that
        // wants the user); `block_in_place` hands this worker's queue to the
        // other so the rest of the process keeps moving.
        let bytes = tokio::task::block_in_place(|| self.0.wrap_key()).map_err(store_error)?;
        bytes.as_slice().try_into().map_err(|_| {
            CoreSecureStoreError::Backend(format!(
                "secure storage returned a {}-byte key, not 32",
                bytes.len()
            ))
        })
    }

    fn rollback_counter(&self) -> Result<u64, CoreSecureStoreError> {
        tokio::task::block_in_place(|| self.0.rollback_counter()).map_err(store_error)
    }

    fn bump_rollback_counter(&self) -> Result<u64, CoreSecureStoreError> {
        tokio::task::block_in_place(|| self.0.bump_rollback_counter()).map_err(store_error)
    }
}

/// A `SecureStore` implemented on the foreign side, as the core sees it.
fn wrap_store(store: Arc<dyn SecureStore>) -> Arc<dyn CoreSecureStore + Send + Sync> {
    Arc::new(FfiKeyStore(store))
}

/// The runtime the SDK's work runs on: process-wide, two workers. Every
/// exported call spawns its work here and awaits the task, so an app with a
/// handle and several clients has one small thread pool, the app's own
/// threads only ever poll a join handle, and the foreign `SecureStore`
/// callbacks run on these threads. Two workers: the calls on one client
/// take turns anyway, so more would only park threads.
fn runtime() -> Result<&'static tokio::runtime::Runtime, ClientError> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("tacenta")
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| internal(e.clone()))
}

/// Run `work` on the SDK's runtime and await its result. Dropping this
/// future (the app cancelled the call) detaches from the task, which runs
/// to completion on its own.
async fn on_runtime<T, W>(work: W) -> Result<T, ClientError>
where
    T: Send + 'static,
    W: Future<Output = Result<T, ClientError>> + Send + 'static,
{
    runtime()?
        .spawn(work)
        .await
        // A fixed string: a panic's payload is the one thing that could put
        // a secret in an error, and it stays on this side of the boundary.
        .unwrap_or_else(|_| Err(internal("the SDK's task failed")))
}

/// An error of this crate's own making (a runtime that would not build, a
/// task that panicked): a bug, so `Internal`.
fn internal(reason: impl Into<String>) -> ClientError {
    ClientError::Internal {
        reason: reason.into(),
    }
}

/// A core address as the foreign side sees it.
fn address_of(a: &DeviceAddr) -> Address {
    Address {
        user: a.user.clone(),
        device: a.device,
    }
}

/// One tenant's handle (decision 0090): built from the API key and
/// the server's name, it fetches the server's service document once to learn
/// where the services are, and signs users up and in. Nothing above it sees a
/// host or a port. Named `Tenant` on these heads (see the crate
/// documentation); the same object is `Tacenta` in Rust and TypeScript.
#[derive(uniffi::Object)]
pub struct Tenant {
    inner: CoreTacenta,
}

#[uniffi::export]
impl Tenant {
    /// Connect to the Tacenta server at `server`, hosted Tacenta by default:
    /// fetch its service document over HTTPS, trusting the public web PKI.
    #[uniffi::constructor(default(server = "tacenta.com"))]
    pub async fn connect(api_key: String, server: String) -> Result<Arc<Tenant>, ClientError> {
        let inner = on_runtime(async move {
            CoreTacenta::connect_to(&api_key, &server)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Arc::new(Tenant { inner }))
    }

    /// Connect by fetching the service document at `url`: the local
    /// development path (`http://127.0.0.1:4780/.well-known/tacenta`, and
    /// `http://` is accepted from loopback only). An `https://` URL is
    /// checked against the public web PKI; a private certificate on the
    /// discovery host is not reachable from these heads yet.
    #[uniffi::constructor]
    pub async fn connect_via(api_key: String, url: String) -> Result<Arc<Tenant>, ClientError> {
        let inner = on_runtime(async move {
            CoreTacenta::connect_via(&api_key, &url, &ClientTls::web_pki())
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Arc::new(Tenant { inner }))
    }

    /// The same tenant, reaching the services over the document's WebSocket
    /// carriage instead of their ports. Fails if the document offers none.
    pub fn websocket(&self) -> Result<Arc<Tenant>, ClientError> {
        let inner = self.inner.clone().websocket()?;
        Ok(Arc::new(Tenant { inner }))
    }

    /// Whether the services are reached over the WebSocket carriage.
    pub fn is_websocket(&self) -> bool {
        self.inner.is_websocket()
    }

    /// Create a user in this tenant.
    pub async fn sign_up(&self, username: String, password: String) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move {
            inner
                .sign_up(&username, &password)
                .await
                .map_err(ClientError::from)
        })
        .await
    }

    /// Sign a user in with a fresh device identity, on device 1 unless
    /// another is given; a connected client. Save `Client.exportState` and
    /// resume with `signInWithState`.
    #[uniffi::method(default(device = 1))]
    pub async fn sign_in(
        &self,
        username: String,
        password: String,
        device: u8,
    ) -> Result<Arc<Client>, ClientError> {
        let inner = self.inner.clone();
        let core = on_runtime(async move {
            inner
                .sign_in_device(&username, &password, device)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Sign in resuming persisted state (identity and live sessions) from
    /// `Client.exportState`.
    #[uniffi::method(default(device = 1))]
    pub async fn sign_in_with_state(
        &self,
        username: String,
        password: String,
        state: Vec<u8>,
        device: u8,
    ) -> Result<Arc<Client>, ClientError> {
        let inner = self.inner.clone();
        let core = on_runtime(async move {
            inner
                .sign_in_with_state(&username, &password, device, &state)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Sign in resuming **sealed** state from `Client.exportStateSealed` with
    /// `store` attached: the rollback-resistant path (decision 0078, anchor
    /// B). A forged or older-than-latest-send state is refused.
    #[uniffi::method(default(device = 1))]
    pub async fn sign_in_with_state_sealed(
        &self,
        username: String,
        password: String,
        state: Vec<u8>,
        store: Arc<dyn SecureStore>,
        device: u8,
    ) -> Result<Arc<Client>, ClientError> {
        let inner = self.inner.clone();
        let store = wrap_store(store);
        let core = on_runtime(async move {
            inner
                .sign_in_with_state_sealed(&username, &password, device, &state, store)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }
}

/// Parse an [`AccountConfig`]'s `host:port` addresses into the core config.
/// The API key and the password arrive apart from the record, so the record
/// (a Kotlin data class with a `toString`, a Swift struct any `print` will
/// reflect) never carries a secret.
fn core_account_config(
    config: AccountConfig,
    api_key: String,
    password: String,
) -> Result<CoreAccountConfig, ClientError> {
    Ok(CoreAccountConfig {
        directory: config
            .directory
            .parse()
            .map_err(|_| invalid("invalid directory address"))?,
        relay: config
            .relay
            .parse()
            .map_err(|_| invalid("invalid relay address"))?,
        accounts: config
            .accounts
            .parse()
            .map_err(|_| invalid("invalid accounts address"))?,
        provisioning: config
            .provisioning
            .parse()
            .map_err(|_| invalid("invalid provisioning address"))?,
        api_key,
        identifier: config.identifier,
        password,
        device: config.device,
    })
}

/// Sign up a new user under a tenant. A control-plane action — create the
/// account, then `Client.signIn` for a connected client. `accounts` is the
/// account service `host:port`; `apiKey` scopes it to the tenant.
#[uniffi::export]
pub async fn sign_up(
    accounts: String,
    api_key: String,
    username: String,
    password: String,
) -> Result<(), ClientError> {
    let addr = accounts
        .parse()
        .map_err(|_| invalid("invalid accounts address"))?;
    on_runtime(async move {
        Core::sign_up(addr, &api_key, &username, &password)
            .await
            .map_err(ClientError::from)
    })
    .await
}

/// Sign up a new user over TLS to a server presenting `serverName`, trusting
/// the public web PKI: the address layer's TLS sibling of [`sign_up`]. An app
/// uses `Tenant.signUp`, which finds the address itself.
#[uniffi::export]
pub async fn sign_up_tls(
    accounts: String,
    server_name: String,
    api_key: String,
    username: String,
    password: String,
) -> Result<(), ClientError> {
    let addr = accounts
        .parse()
        .map_err(|_| invalid("invalid accounts address"))?;
    let tls = ClientTls::web_pki();
    on_runtime(async move {
        Core::sign_up_tls(addr, &server_name, &tls, &api_key, &username, &password)
            .await
            .map_err(ClientError::from)
    })
    .await
}

/// A connected client: one signed-in user on one device. Every call is
/// async. The calls take turns on the client, but a pending `receive`
/// waits for mail outside that turn, so a `send` on the same client from
/// another task goes through meanwhile. The `Config`/`AccountConfig`
/// constructors below are the address layer under the [`Tenant`] handle,
/// for callers that know their addresses.
#[derive(uniffi::Object)]
pub struct Client {
    /// Fixed at sign-in for the client's life, so `address()` needs no lock.
    address: Address,
    inner: Arc<Mutex<Core>>,
    /// Pinged when mail may be waiting; `receive` waits on it outside the
    /// lock, so a `send` goes through while a receive is pending.
    mail: tacenta_client::MailSignal,
    /// The one `receive` in flight, shared by every caller awaiting it. A
    /// caller that is cancelled drops its clone; the batch lands here and
    /// the next call returns it, so nothing decrypted is lost.
    inbound: Mutex<Option<Pending>>,
    /// Dropped with the client, which ends a receive task that is waiting
    /// for mail: the task holds the core weakly, so a released client does
    /// not live on as an orphan that reconnects and takes the device's mail.
    _alive: tokio::sync::watch::Sender<()>,
    released: tokio::sync::watch::Receiver<()>,
}

type Pending = Shared<Pin<Box<dyn Future<Output = Result<Vec<Message>, ClientError>> + Send>>>;

impl Client {
    fn new(core: Core) -> Arc<Client> {
        let (alive, released) = tokio::sync::watch::channel(());
        Arc::new(Client {
            address: address_of(core.address()),
            mail: core.mail(),
            inner: Arc::new(Mutex::new(core)),
            inbound: Mutex::new(None),
            _alive: alive,
            released,
        })
    }
}

/// A client's inbound messages one at a time, from `Client.inbound`: each
/// `next` is the next message in the order the relay delivered it,
/// awaiting mail when nothing is buffered. It is `receive` flattened, on
/// the same single-flight wait underneath. Swift iterates it as an
/// `AsyncSequence` (`for try await message in client.inbound()`), Kotlin
/// collects `asFlow()`; both are thin hand-written wrappers over `next`.
/// It holds the client, so a loop over it keeps the client alive, and
/// releasing both ends the wait. A message goes to whichever `next` is
/// waiting, so run one loop per client.
#[derive(uniffi::Object)]
pub struct Inbound {
    client: Arc<Client>,
    buffered: Mutex<VecDeque<Message>>,
}

#[uniffi::export]
impl Inbound {
    /// The next message, awaiting mail if none is buffered.
    pub async fn next(&self) -> Result<Message, ClientError> {
        // The buffer stays locked across the wait, so two callers on one
        // `Inbound` take turns rather than both draining the batch.
        let mut buffered = self.buffered.lock().await;
        loop {
            if let Some(message) = buffered.pop_front() {
                return Ok(message);
            }
            buffered.extend(self.client.receive().await?);
        }
    }
}

/// Parse a [`Config`]'s `host:port` addresses into the core config.
fn core_config(config: Config) -> Result<CoreConfig, ClientError> {
    Ok(CoreConfig {
        directory: config
            .directory
            .parse()
            .map_err(|_| invalid("invalid directory address"))?,
        relay: config
            .relay
            .parse()
            .map_err(|_| invalid("invalid relay address"))?,
        user: config.user,
        device: config.device,
    })
}

#[uniffi::export]
impl Client {
    /// Connect to a server and authenticate.
    #[uniffi::constructor]
    pub async fn connect(config: Config) -> Result<Arc<Client>, ClientError> {
        let core_config = core_config(config)?;
        let core =
            on_runtime(async move { Core::connect(&core_config).await.map_err(ClientError::from) })
                .await?;
        Ok(Client::new(core))
    }

    /// Sign in to an account and provision this device, returning a client
    /// operating under the account's handle. Save
    /// `exportIdentity` and reconnect with `signInWithIdentity` on later runs.
    #[uniffi::constructor]
    pub async fn sign_in(
        config: AccountConfig,
        api_key: String,
        password: String,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_account_config(config, api_key, password)?;
        let core =
            on_runtime(async move { Core::sign_in(&core_config).await.map_err(ClientError::from) })
                .await?;
        Ok(Client::new(core))
    }

    /// Sign in over TLS to a server presenting `serverName`, trusting the
    /// public web PKI: the address layer's TLS sibling of `signIn`. An app
    /// uses `Tenant.signIn`, which finds the addresses itself.
    #[uniffi::constructor]
    pub async fn sign_in_tls(
        config: AccountConfig,
        server_name: String,
        api_key: String,
        password: String,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_account_config(config, api_key, password)?;
        let tls = ClientTls::web_pki();
        let core = on_runtime(async move {
            Core::sign_in_tls(&core_config, &server_name, &tls)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Sign in and provision under a saved device identity (from
    /// `exportIdentity`), keeping the same bound key across restarts.
    #[uniffi::constructor]
    pub async fn sign_in_with_identity(
        config: AccountConfig,
        identity: Vec<u8>,
        api_key: String,
        password: String,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_account_config(config, api_key, password)?;
        let core = on_runtime(async move {
            Core::sign_in_with_identity(&core_config, &identity)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Sign in and restore a **full session state** saved by `exportState`.
    ///
    /// **This is the difference between keeping an identity and keeping a
    /// conversation.** `signInWithIdentity` restores who you are, and every
    /// live ratchet starts again from nothing; this restores the ratchets too,
    /// so messages already in flight still decrypt after a restart. Both forms
    /// are offered here, as the Rust client offers them (decision 0051).
    #[uniffi::constructor]
    pub async fn sign_in_with_state(
        config: AccountConfig,
        state: Vec<u8>,
        api_key: String,
        password: String,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_account_config(config, api_key, password)?;
        let core = on_runtime(async move {
            Core::sign_in_with_state(&core_config, &state)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Connect without an account, restoring a full session state saved by
    /// `exportState`. The no-account sibling of `signInWithState`.
    #[uniffi::constructor]
    pub async fn connect_with_state(
        config: Config,
        state: Vec<u8>,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_config(config)?;
        let core = on_runtime(async move {
            Core::connect_with_state(&core_config, &state)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Restore a **sealed** state (from `exportStateSealed`) — decision 0078's
    /// anchor B, the rollback-resistant restore path. It attaches `store` (so
    /// per-send commits resume) and refuses a forged state, catches a state
    /// older than the latest send via the store counter, and witnesses the
    /// generation to the directory — closing the rollback gap against a file-rewriter given
    /// a rollback-resistant store. The account sibling is `signInWithStateSealed`.
    #[uniffi::constructor]
    pub async fn connect_with_state_sealed(
        config: Config,
        state: Vec<u8>,
        store: Arc<dyn SecureStore>,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_config(config)?;
        let ks = wrap_store(store);
        let core = on_runtime(async move {
            Core::connect_with_state_sealed(&core_config, &state, ks)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// Sign in and restore a **sealed** state (from `exportStateSealed`) — the
    /// account-path sibling of `connectWithStateSealed`, and the rollback-resistant
    /// sign-in path (decision 0078, anchor B). Attaches `store`; a forged or
    /// older-than-latest-send state is refused, and the generation is witnessed to
    /// the directory — closing the rollback gap against a file-rewriter given a
    /// rollback-resistant store.
    #[uniffi::constructor]
    pub async fn sign_in_with_state_sealed(
        config: AccountConfig,
        state: Vec<u8>,
        store: Arc<dyn SecureStore>,
        api_key: String,
        password: String,
    ) -> Result<Arc<Client>, ClientError> {
        let core_config = core_account_config(config, api_key, password)?;
        let ks = wrap_store(store);
        let core = on_runtime(async move {
            Core::sign_in_with_state_sealed(&core_config, &state, ks)
                .await
                .map_err(ClientError::from)
        })
        .await?;
        Ok(Client::new(core))
    }

    /// This client's own address.
    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// What the sign-in found: whether restored sessions are in use or were
    /// discarded as a rollback; see [`RestoreOutcome`].
    pub async fn restore_outcome(&self) -> Result<RestoreOutcome, ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move { Ok(inner.lock().await.restore_outcome().into()) }).await
    }

    /// Encrypt and send a message to a peer; returns once routed.
    pub async fn send(&self, to: Address, message: Vec<u8>) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move {
            let mut core = inner.lock().await;
            core.send(&DeviceAddr::new(to.user, to.device), &message)
                .await
                .map_err(ClientError::from)
        })
        .await
    }

    /// Inbound messages one at a time, as they arrive: see [`Inbound`].
    pub fn inbound(self: Arc<Self>) -> Arc<Inbound> {
        Arc::new(Inbound {
            client: self,
            buffered: Mutex::new(VecDeque::new()),
        })
    }

    /// Await the next mail, then return every pending message decrypted and
    /// attributed to its sender.
    pub async fn receive(&self) -> Result<Vec<Message>, ClientError> {
        // One receive in flight per client, shared by whoever awaits it.
        let inbound = {
            let mut slot = self.inbound.lock().await;
            // A finished error nobody collected (the caller was cancelled and
            // the link has since recovered) is not this call's answer.
            if slot
                .as_ref()
                .is_some_and(|pending| matches!(pending.peek(), Some(Err(_))))
            {
                *slot = None;
            }
            match slot.as_ref() {
                Some(pending) => pending.clone(),
                None => {
                    let inner = Arc::downgrade(&self.inner);
                    let mail = self.mail.clone();
                    let mut released = self.released.clone();
                    let task = runtime()?.spawn(async move {
                        // Poll under the lock, wait for mail outside it: a
                        // send on this client goes through meanwhile. The
                        // core is held only around the poll, so a client the
                        // app released ends this task at the next wake.
                        loop {
                            let Some(inner) = inner.upgrade() else {
                                return Err(internal("the client was released"));
                            };
                            let received = inner.lock().await.drain().await?;
                            drop(inner);
                            if !received.is_empty() {
                                return Ok(received
                                    .into_iter()
                                    .map(|r| Message {
                                        from: address_of(&r.from),
                                        plaintext: r.plaintext,
                                    })
                                    .collect::<Vec<Message>>());
                            }
                            tokio::select! {
                                _ = mail.wait() => {}
                                _ = released.changed() => {
                                    return Err(internal("the client was released"));
                                }
                            }
                        }
                    });
                    let joined: Pin<
                        Box<dyn Future<Output = Result<Vec<Message>, ClientError>> + Send>,
                    > = Box::pin(async move {
                        task.await
                            .unwrap_or_else(|_| Err(internal("the SDK's task failed")))
                    });
                    let pending: Pending = joined.shared();
                    *slot = Some(pending.clone());
                    pending
                }
            }
        };
        let batch = inbound.await;
        // Delivered: the next call starts a fresh wait. A caller cancelled
        // while waiting left its clone behind; the batch stayed in the slot
        // for this call rather than being lost.
        let mut slot = self.inbound.lock().await;
        if slot
            .as_ref()
            .is_some_and(|pending| pending.peek().is_some())
        {
            *slot = None;
        }
        batch
    }

    /// Resolve a username within this client's tenant to a contact, or `None`
    /// if no such user is registered. Exact resolution only.
    pub async fn find(&self, username: String) -> Result<Option<Contact>, ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move {
            let mut core = inner.lock().await;
            let found = core.find(&username).await?;
            Ok(found.map(|c| Contact {
                address: address_of(&c.address),
            }))
        })
        .await
    }

    /// The device identity secret, to persist and reuse via
    /// `signInWithIdentity` (and `connectWithIdentity`) on later runs. Carries
    /// a private key — store it as a secret.
    pub async fn export_identity(&self) -> Result<Vec<u8>, ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move { Ok(inner.lock().await.export_identity()) }).await
    }

    /// The resumable session state: the device identity, every **live ratchet
    /// session** with a peer this device already talks to, and the **published
    /// prekey secrets**. Restore it with `signInWithState` or
    /// `connectWithState`.
    ///
    /// **First contact is covered.** A message a *new* peer sends while this
    /// device is offline is encrypted to a one-time prekey from the published
    /// bundle; the private half of that prekey travels in this blob, so after a
    /// restore the queued first-contact message still decrypts, and live
    /// conversations resume mid-ratchet.
    ///
    /// **Carries private keys, and it is not a backup.** Restoring an older
    /// copy rewinds ratchets that have already moved. This unsealed export has no
    /// rollback defence: its generation counter is plaintext a file-rewriter can
    /// forge. Store the most recent one, replace it
    /// in place, and do not keep a history of them. For the rollback-resistant
    /// form, use `exportStateSealed` with a `SecureStore` — it authenticates the
    /// state under a platform-secure-storage key so a rewritten file is refused
    /// on restore.
    pub async fn export_state(&self) -> Result<Vec<u8>, ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move {
            let core = inner.lock().await;
            core.export_state().await.map_err(ClientError::from)
        })
        .await
    }

    /// Turn on **per-send rollback protection**: hold `store` so every `send`
    /// and every ratchet-advancing `receive` commits a monotonic counter to it,
    /// and `exportStateSealed` binds that counter. Call once, before sending, on
    /// a client made by `connect` / `signIn`; the sealed restore constructors
    /// attach the store themselves. This is what closes the per-send window —
    /// use the same platform `store` across restarts so the counter is monotone.
    pub async fn attach_secure_store(
        &self,
        store: Arc<dyn SecureStore>,
    ) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        let ks = wrap_store(store);
        on_runtime(async move {
            inner
                .lock()
                .await
                .attach_secure_store(ks)
                .map_err(ClientError::from)
        })
        .await
    }

    /// The **sealed** resumable state (decision 0078, anchor B): the same bytes
    /// as `exportState`, authenticated under the attached `SecureStore` key so
    /// that an attacker who can rewrite the state file cannot forge the
    /// anti-rollback generation, with the store's rollback counter bound
    /// alongside. Restore with `connectWithStateSealed` or `signInWithStateSealed`.
    /// **Requires `attachSecureStore` first** (or a sealed restore, which attaches
    /// it); errors otherwise. Against a file-rewriter this refuses a forged
    /// generation and, via the per-send counter, a state older than the latest
    /// send.
    ///
    /// The seal authenticates but does not encrypt: the bytes still carry
    /// secrets and must be stored encrypted at rest.
    pub async fn export_state_sealed(&self) -> Result<Vec<u8>, ClientError> {
        let inner = self.inner.clone();
        on_runtime(async move {
            let core = inner.lock().await;
            core.export_state_sealed().await.map_err(ClientError::from)
        })
        .await
    }
}
