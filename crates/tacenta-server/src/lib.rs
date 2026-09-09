//! The Tacenta server: the directory service and the relay server bound
//! over one shared directory, so a client can point at a running instance.
//!
//! This is the demo's wiring made into a real, reusable server. The two
//! server-side crypto verifiers live here — [`IdentityAuth`] (relay
//! connection auth) and [`PossessionCheck`] (registration proof of
//! possession) — because they are the same on every deployment; the
//! crypto-free transport takes them as the injected `Authenticator` and
//! `Possession`. A single `Arc<Mutex<Directory>>` backs both services: the
//! directory service writes registrations, and the relay authenticator
//! reads them (decision record 0020).
//!
//! With a data directory configured, the server loads its snapshots on
//! [`Server::bind`] and writes them back on graceful shutdown (SIGINT or
//! SIGTERM) and on `snapshot_interval` if one is set, so registrations, queues,
//! and accounts
//! (tenants, users, API keys, sessions) survive a restart (decision record
//! 0022). A crash still loses work back to the last snapshot; what it cannot
//! do is leave a snapshot torn, because each file is written through
//! [`tacenta_core::persist::write_atomically`].
//!
//! **That last point is load-bearing rather than tidy.** A corrupt snapshot is
//! deliberately fatal at startup (see `load`), so a torn write would not
//! degrade the server, it would stop the server booting until an operator
//! deleted the file by hand. A plain `fs::write` here would trade "a restart
//! loses state" for "a crash during a snapshot may prevent the next start".
//! The atomic write is what makes a data directory safe to turn on.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rand::{RngCore as _, TryRngCore as _};
use tacenta_accounts::{AccountStore, Accounts};
use tacenta_core::crypto::verify_challenge;
use tacenta_core::persist::write_atomically;
use tacenta_directory::{DEFAULT_MAX_PER_WINDOW, Directory, Registration};
use tacenta_relay::{DeviceAddr, Relay};
use tacenta_transport::{
    Authenticator, Possession, ProvisionOutcome, ProvisionRequest, Provisioner, ServeLimits,
    Server as RelayServer, ServerTls, account_server, dir_server_gated,
    serve_accounts_tls_with_limits, serve_accounts_with_limits, serve_directory_tls_with_limits,
    serve_directory_with_limits, serve_provisioning_tls_with_limits,
    serve_provisioning_with_limits, serve_tls_with_limits, serve_with_limits, server,
};
use tokio::net::TcpListener;

/// Re-exported so a caller configuring [`Config::registration_policy`] can name
/// the policy without depending on `tacenta-transport` directly.
pub use tacenta_transport::RegistrationPolicy;

type ServiceFuture = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

const DIRECTORY_SNAPSHOT: &str = "directory.snapshot";
const RELAY_SNAPSHOT: &str = "relay.snapshot";
const ACCOUNTS_SNAPSHOT: &str = "accounts.snapshot";

/// A fresh 32-byte challenge for one connection.
fn fresh_challenge() -> Vec<u8> {
    let mut c = vec![0u8; 32];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut c);
    c
}

/// Relay connection authenticator: reads a device's identity key from the
/// shared directory and verifies its signature over the challenge. The
/// directory holds only public bytes; the cryptography is here.
pub struct IdentityAuth {
    directory: Arc<Mutex<Directory>>,
}

impl IdentityAuth {
    pub fn new(directory: Arc<Mutex<Directory>>) -> IdentityAuth {
        IdentityAuth { directory }
    }
}

impl Authenticator for IdentityAuth {
    fn challenge(&self) -> Vec<u8> {
        fresh_challenge()
    }

    fn verify(&self, device: &DeviceAddr, challenge: &[u8], signature: &[u8]) -> bool {
        // Copy the identity bytes out under the lock, then verify without
        // holding it.
        let identity = {
            let dir = self.directory.lock().expect("directory mutex poisoned");
            match dir.identity(device) {
                Some(bytes) => bytes.to_vec(),
                None => return false,
            }
        };
        verify_challenge(&identity, challenge, signature)
    }

    /// A deployment with a directory knows exactly who exists, so it overrides
    /// the permissive default and refuses sends to strangers.
    fn knows_recipient(&self, device: &DeviceAddr) -> bool {
        self.is_registered(device)
    }
}

impl IdentityAuth {
    /// The registration view the relay transport needs to refuse a `Send` to
    /// an address nobody has registered.
    ///
    /// Read-only and cheap: it asks the same map `verify` already consults.
    fn is_registered(&self, device: &DeviceAddr) -> bool {
        self.directory
            .lock()
            .expect("directory mutex poisoned")
            .identity(device)
            .is_some()
    }
}

/// Registration proof-of-possession verifier: the submitted identity key
/// must have signed the challenge (decision record 0019).
pub struct PossessionCheck;

impl Possession for PossessionCheck {
    fn challenge(&self) -> Vec<u8> {
        fresh_challenge()
    }

    fn verify(&self, identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
        verify_challenge(identity, challenge, signature)
    }
}

/// Device provisioning: validate a session token, verify the device's proof of
/// possession, and bind its identity into the directory under the account's
/// handle. Holds the accounts store (which resolves the session to a handle)
/// and the directory (the write); the crypto is here. This is the one place
/// the account layer and the directory meet — the directory itself stays
/// account-agnostic (decision record 0033).
pub struct AccountProvisioner {
    accounts: Arc<AccountStore>,
    directory: Arc<Mutex<Directory>>,
}

impl AccountProvisioner {
    pub fn new(
        accounts: Arc<AccountStore>,
        directory: Arc<Mutex<Directory>>,
    ) -> AccountProvisioner {
        AccountProvisioner {
            accounts,
            directory,
        }
    }
}

impl Provisioner for AccountProvisioner {
    fn challenge(&self) -> Vec<u8> {
        fresh_challenge()
    }

    async fn provision(&self, request: &ProvisionRequest, challenge: &[u8]) -> ProvisionOutcome {
        // Resolve the session to its directory handle.
        let handle = match self.accounts.validate_session(&request.session_token).await {
            Ok(Some((tenant, username))) => match self.accounts.handle(&tenant, &username).await {
                Ok(Some(handle)) => handle,
                Ok(None) => return ProvisionOutcome::BadSession,
                Err(_) => return ProvisionOutcome::ServerError,
            },
            Ok(None) => return ProvisionOutcome::BadSession,
            Err(_) => return ProvisionOutcome::ServerError,
        };
        // Verify possession of the identity key — synchronous crypto.
        let proven = verify_challenge(&request.identity, challenge, &request.possession_sig);
        if !proven {
            return ProvisionOutcome::PossessionFailed;
        }
        // Bind the identity to the handle in the directory (trust on first use).
        // The client chose neither the handle (it comes from the session) nor
        // gets to overwrite a binding it does not own.
        let addr = DeviceAddr::new(handle.clone(), request.device);
        let outcome = self
            .directory
            .lock()
            .expect("directory mutex poisoned")
            .register(&addr, request.identity.clone(), request.bundle.clone());
        match outcome {
            Registration::Registered | Registration::Refreshed => {
                ProvisionOutcome::Provisioned { handle }
            }
            Registration::Rejected => ProvisionOutcome::Rejected,
        }
    }
}

/// PEM file paths for the server's TLS certificate and private key.
#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

/// Where the server listens, where it persists, and whether it serves TLS.
/// The directory service and the relay server bind separate ports on the
/// same address. With `data_dir` set, state is loaded on bind and saved on
/// shutdown. With `tls` set, both services serve over TLS.
#[derive(Clone, Debug)]
pub struct Config {
    pub bind: IpAddr,
    pub directory_port: u16,
    pub relay_port: u16,
    pub accounts_port: u16,
    pub provisioning_port: u16,
    pub data_dir: Option<PathBuf>,
    /// A PostgreSQL connection string. When set (and the `postgres` feature is
    /// compiled in), accounts run on Postgres — durable, no snapshot — instead
    /// of the in-memory snapshot store. Ignored for directory and relay, which
    /// still snapshot.
    pub database_url: Option<String>,
    pub tls: Option<TlsFiles>,
    /// Persist the whole state to `data_dir` on this interval as well as on
    /// shutdown, narrowing what a crash loses. Ignored without `data_dir`.
    pub snapshot_interval: Option<std::time::Duration>,
    /// The relay's whole-node memory ceiling — total unacknowledged bytes across
    /// every user — in bytes. `None` uses the relay's built-in default
    /// ([`tacenta_relay::MAX_TOTAL_BYTES`], 4 GiB). Set this from the node's RAM:
    /// it is the layer that bounds `registered users × MAX_USER_BYTES` on a public
    /// self-service listener. Applied to a freshly built *and* a restored relay,
    /// since the ceiling is node configuration, not persisted state.
    pub relay_max_total_bytes: Option<u64>,
    /// New handle registrations allowed per source IP per hour on the directory
    /// (decision 0079). `None` uses the built-in default
    /// ([`tacenta_directory::DEFAULT_MAX_PER_WINDOW`]). Only *new* bindings are
    /// throttled; a returning client re-confirming its handle is never limited.
    /// Raise it for NAT headroom on a shared-address deployment.
    pub registration_max_per_hour: Option<usize>,
    /// How new raw-handle registration is admitted (layer 2, decision 0080).
    /// `None` uses [`RegistrationPolicy::Open`]. Set `AccountsOnly` to close
    /// unauthenticated self-registration so handles come only through account
    /// provisioning — the absolute-bound layer for a public deployment.
    pub registration_policy: Option<RegistrationPolicy>,
    /// The most connections any one of the four listeners will serve at
    /// once. `None` uses the transport's built-in
    /// default ([`ServeLimits`]); past the cap a new connection is closed at
    /// once rather than queued. Set it from the node's file-descriptor budget
    /// on a public listener.
    pub max_connections: Option<usize>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // The one place the defaults live: the service document a client
            // discovers them from names the same numbers.
            directory_port: tacenta_discovery::DEFAULT_PORTS[0],
            relay_port: tacenta_discovery::DEFAULT_PORTS[1],
            accounts_port: tacenta_discovery::DEFAULT_PORTS[2],
            provisioning_port: tacenta_discovery::DEFAULT_PORTS[3],
            data_dir: None,
            database_url: None,
            tls: None,
            snapshot_interval: None,
            relay_max_total_bytes: None,
            registration_max_per_hour: None,
            registration_policy: None,
            max_connections: None,
        }
    }
}

/// Load a snapshot file, restoring with `restore`. Returns the `default`
/// when the file is absent (first run), and an error when it is present but
/// unreadable or corrupt — a corrupt snapshot fails startup rather than
/// silently discarding state.
fn load<T>(
    path: &Path,
    restore: impl FnOnce(&[u8]) -> Option<T>,
    default: impl FnOnce() -> T,
) -> std::io::Result<T> {
    match std::fs::read(path) {
        Ok(bytes) => restore(&bytes).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt snapshot at {}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(default()),
        Err(e) => Err(e),
    }
}

/// Connect the account store to a database, running migrations. With the
/// `postgres` feature off, a set `database_url` is a configuration error rather
/// than a silent fall-back to the in-memory store.
#[cfg(feature = "postgres")]
async fn connect_accounts(url: &str) -> std::io::Result<Arc<AccountStore>> {
    let pg = tacenta_accounts::pg::PgAccounts::connect(url)
        .await
        .map_err(std::io::Error::other)?;
    pg.migrate().await.map_err(std::io::Error::other)?;
    Ok(Arc::new(AccountStore::postgres(pg)))
}

#[cfg(not(feature = "postgres"))]
async fn connect_accounts(_url: &str) -> std::io::Result<Arc<AccountStore>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "database_url is set but the server was built without the `postgres` feature",
    ))
}

/// Both listeners bound over a shared directory, ready to serve. Split from
/// [`Server::serve`] so the actual listening addresses are readable (e.g.
/// after binding port 0) before serving.
pub struct Server {
    directory: Arc<Mutex<Directory>>,
    relay: Arc<RelayServer<IdentityAuth>>,
    accounts: Arc<AccountStore>,
    dir_listener: TcpListener,
    relay_listener: TcpListener,
    accounts_listener: TcpListener,
    provisioning_listener: TcpListener,
    data_dir: Option<PathBuf>,
    tls: Option<ServerTls>,
    snapshot_interval: Option<std::time::Duration>,
    registration_max_per_hour: usize,
    registration_policy: RegistrationPolicy,
    limits: ServeLimits,
}

impl Server {
    /// Bind the directory and relay listeners per `config`. With
    /// `config.data_dir` set, load both snapshots (creating the directory
    /// if needed); otherwise start empty.
    pub async fn bind(config: &Config) -> std::io::Result<Server> {
        let (directory, relay) = match &config.data_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)?;
                (
                    load(
                        &dir.join(DIRECTORY_SNAPSHOT),
                        Directory::restore,
                        Directory::new,
                    )?,
                    load(&dir.join(RELAY_SNAPSHOT), Relay::restore, Relay::new)?,
                )
            }
            None => (Directory::new(), Relay::new()),
        };

        // The whole-node memory ceiling is deployment configuration, not
        // persisted state, so it is applied here to whichever relay we built —
        // freshly or restored — rather than carried in the snapshot.
        let relay = match config.relay_max_total_bytes {
            Some(limit) => relay.with_max_total_bytes(limit),
            None => relay,
        };

        let tls = match &config.tls {
            Some(files) => {
                let cert = std::fs::read(&files.cert_pem)?;
                let key = std::fs::read(&files.key_pem)?;
                Some(ServerTls::from_pem(&cert, &key)?)
            }
            None => None,
        };

        let directory = Arc::new(Mutex::new(directory));
        let relay = server(relay, IdentityAuth::new(directory.clone()));
        // Accounts snapshot alongside the directory and relay (decision record
        // 0022): loaded on bind, saved on shutdown and on the periodic tick, so
        // tenants, users, API keys, and sessions survive a restart. The durable
        // store (decision record 0030) replaces all three snapshots later.
        let accounts = if let Some(url) = &config.database_url {
            connect_accounts(url).await?
        } else {
            let accounts = match &config.data_dir {
                Some(dir) => load(
                    &dir.join(ACCOUNTS_SNAPSHOT),
                    Accounts::restore,
                    Accounts::new,
                )?,
                None => Accounts::new(),
            };
            Arc::new(AccountStore::memory(accounts))
        };
        let dir_listener = TcpListener::bind((config.bind, config.directory_port)).await?;
        let relay_listener = TcpListener::bind((config.bind, config.relay_port)).await?;
        let accounts_listener = TcpListener::bind((config.bind, config.accounts_port)).await?;
        let provisioning_listener =
            TcpListener::bind((config.bind, config.provisioning_port)).await?;
        Ok(Server {
            directory,
            relay,
            accounts,
            dir_listener,
            relay_listener,
            accounts_listener,
            provisioning_listener,
            data_dir: config.data_dir.clone(),
            tls,
            snapshot_interval: config.snapshot_interval,
            registration_max_per_hour: config
                .registration_max_per_hour
                .unwrap_or(DEFAULT_MAX_PER_WINDOW),
            registration_policy: config.registration_policy.unwrap_or_default(),
            limits: ServeLimits {
                max_connections: config
                    .max_connections
                    .unwrap_or_else(|| ServeLimits::default().max_connections),
                ..ServeLimits::default()
            },
        })
    }

    /// Whether this server is serving TLS.
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The address the directory service is listening on.
    pub fn directory_addr(&self) -> std::io::Result<SocketAddr> {
        self.dir_listener.local_addr()
    }

    /// The address the relay server is listening on.
    pub fn relay_addr(&self) -> std::io::Result<SocketAddr> {
        self.relay_listener.local_addr()
    }

    /// The address the account service is listening on.
    pub fn accounts_addr(&self) -> std::io::Result<SocketAddr> {
        self.accounts_listener.local_addr()
    }

    /// The address the provisioning service is listening on.
    pub fn provisioning_addr(&self) -> std::io::Result<SocketAddr> {
        self.provisioning_listener.local_addr()
    }

    /// Serve both services over the shared directory until Ctrl-C or a fatal
    /// accept error on either listener, then persist (if configured) and
    /// return.
    pub async fn serve(self) -> std::io::Result<()> {
        self.serve_until(std::future::pending::<()>()).await
    }

    /// Serve until `shutdown` resolves, Ctrl-C arrives, or a fatal accept
    /// error occurs, then persist (if configured) and return. [`Server::serve`]
    /// is this with a shutdown that never resolves; a caller embedding the
    /// server passes its own stop signal.
    pub async fn serve_until(self, shutdown: impl Future<Output = ()>) -> std::io::Result<()> {
        let dir_hub = dir_server_gated(
            self.directory.clone(),
            PossessionCheck,
            self.registration_max_per_hour,
            self.registration_policy,
        );
        let relay_hub = self.relay.clone();

        // The framed protocol is identical over TCP and TLS; only the accept
        // wrapper differs. Box the two so the branch does not leak into the
        // select. Both are Unpin, so they can be re-polled by `&mut` across
        // periodic ticks.
        let limits = self.limits;
        let mut dir_service: ServiceFuture = match self.tls.clone() {
            Some(tls) => Box::pin(serve_directory_tls_with_limits(
                self.dir_listener,
                dir_hub,
                tls,
                limits,
            )),
            None => Box::pin(serve_directory_with_limits(
                self.dir_listener,
                dir_hub,
                limits,
            )),
        };
        let mut relay_service: ServiceFuture = match self.tls.clone() {
            Some(tls) => Box::pin(serve_tls_with_limits(
                self.relay_listener,
                relay_hub,
                tls,
                limits,
            )),
            None => Box::pin(serve_with_limits(self.relay_listener, relay_hub, limits)),
        };
        let accounts_hub = account_server(self.accounts.clone());
        let mut accounts_service: ServiceFuture = match self.tls.clone() {
            Some(tls) => Box::pin(serve_accounts_tls_with_limits(
                self.accounts_listener,
                accounts_hub,
                tls,
                limits,
            )),
            None => Box::pin(serve_accounts_with_limits(
                self.accounts_listener,
                accounts_hub,
                limits,
            )),
        };
        let provisioner = Arc::new(AccountProvisioner::new(
            self.accounts.clone(),
            self.directory.clone(),
        ));
        let mut provisioning_service: ServiceFuture = match self.tls.clone() {
            Some(tls) => Box::pin(serve_provisioning_tls_with_limits(
                self.provisioning_listener,
                provisioner,
                tls,
                limits,
            )),
            None => Box::pin(serve_provisioning_with_limits(
                self.provisioning_listener,
                provisioner,
                limits,
            )),
        };
        tokio::pin!(shutdown);
        let sig = shutdown_signal();
        tokio::pin!(sig);

        let outcome = match self.snapshot_interval {
            Some(period) => {
                let mut ticker = tokio::time::interval(period);
                ticker.tick().await; // consume the immediate first tick
                loop {
                    tokio::select! {
                        r = &mut dir_service => break r,
                        r = &mut relay_service => break r,
                        r = &mut accounts_service => break r,
                        r = &mut provisioning_service => break r,
                        _ = &mut shutdown => break Ok(()),
                        _ = &mut sig => break Ok(()),
                        _ = ticker.tick() => {
                            // Housekeeping first: drop expired sessions so the
                            // store does not grow without bound. Best-effort —
                            // a sweep failure is not fatal to serving.
                            let _ = self.accounts.sweep_expired_sessions().await;
                            // A write error ends serving so the operator
                            // notices, rather than silently drifting.
                            persist_state(&self.data_dir, &self.directory, &self.relay, &self.accounts)?;
                        }
                    }
                }
            }
            None => tokio::select! {
                r = &mut dir_service => r,
                r = &mut relay_service => r,
                r = &mut accounts_service => r,
                r = &mut provisioning_service => r,
                _ = &mut shutdown => Ok(()),
                _ = &mut sig => Ok(()),
            },
        };

        // Persist on the way out regardless of why we stopped; a snapshot of
        // consistent in-memory state is worth writing even after an accept
        // error. Surface an accept error after saving.
        let persisted = persist_state(&self.data_dir, &self.directory, &self.relay, &self.accounts);
        outcome.and(persisted)
    }

    /// Write the current directory and relay state to the data directory
    /// now. A no-op when no data directory is configured. Useful for a
    /// periodic snapshot alongside the shutdown save.
    pub fn persist(&self) -> std::io::Result<()> {
        persist_state(&self.data_dir, &self.directory, &self.relay, &self.accounts)
    }
}

/// Snapshot the directory and relay to the data directory. Shared by the
/// shutdown path (where `self` is partially moved into the service futures)
/// and the public [`Server::persist`].
///
/// Each file is written atomically and durably, so no individual snapshot can
/// be torn by a crash. **The set of them is not written atomically**, and that
/// is worth stating rather than leaving to be found: a crash between the
/// directory write and the relay write leaves a new directory snapshot beside
/// an older relay snapshot. The result is a consistent server whose queues lag
/// its registrations — a device may be registered with no queue, or hold a
/// queue naming a device the directory has since replaced. Neither loses
/// message confidentiality and neither blocks startup; a queue that outlives
/// its registration is unreachable because relay auth reads the directory.
///
/// Making the set atomic means one combined snapshot file, the shape decision
/// 0077 chose for the client store. It is the right end state and it is not
/// done here.
fn persist_state(
    data_dir: &Option<PathBuf>,
    directory: &Arc<Mutex<Directory>>,
    relay: &Arc<RelayServer<IdentityAuth>>,
    accounts: &Arc<AccountStore>,
) -> std::io::Result<()> {
    let Some(dir) = data_dir else {
        return Ok(());
    };
    let directory_bytes = directory
        .lock()
        .expect("directory mutex poisoned")
        .snapshot();
    write_atomically(&dir.join(DIRECTORY_SNAPSHOT), &directory_bytes)?;
    write_atomically(&dir.join(RELAY_SNAPSHOT), &relay.snapshot())?;
    // A durable backend (Postgres) persists itself and returns no snapshot.
    if let Some(accounts_bytes) = accounts.snapshot() {
        write_atomically(&dir.join(ACCOUNTS_SNAPSHOT), &accounts_bytes)?;
    }
    Ok(())
}

/// Resolve when the process is asked to stop: SIGINT (Ctrl-C) or SIGTERM.
///
/// **SIGTERM is the one that matters in production.** `ctrl_c()` on Unix is
/// SIGINT only, while a container runtime or service manager stops a process
/// with SIGTERM; waiting on SIGINT alone would leave the graceful path, and
/// the shutdown snapshot, unreached under a normal stop. So both are waited
/// on. Every in-process test drives shutdown through `serve_until` and never
/// goes near a signal, which is why `tests/sigterm.rs` signals a real process.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            // Registration can only fail on a broken platform; fall back to
            // SIGINT alone rather than refuse to start.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
