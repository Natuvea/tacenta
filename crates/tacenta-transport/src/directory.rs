//! A TCP transport for the directory service: register public key
//! material, or look a device up, over a socket.
//!
//! It mirrors the relay transport's shape, minus push — the directory is
//! plain request/response, so a client writes a request and reads the
//! reply on the same stream, no demultiplexing needed. On connect the
//! server issues one challenge; a `Register` carries a signature over it,
//! the registrant's proof of possession of the identity key it submits
//! (decision record 0019). A `Rotate` carries two signatures — possession
//! of the new key and an authorization by the currently bound key —
//! replacing the binding along a continuity chain (decision record 0024).
//! The server delegates every signature check to an injected [`Possession`]
//! verifier — the crypto stays out of the transport, just as connection
//! auth does — then applies the trust rule through the crypto-free
//! `Directory`. Lookups need no proof; the material is public.

use crate::{read_frame, write_frame};
use std::sync::{Arc, Mutex};
use tacenta_directory::{
    DEFAULT_MAX_PER_WINDOW, DirRequest, DirResponse, Directory, RegistrationLimiter,
    decode_dir_response, encode_dir_request,
};
// Used only by the native-only connection-serving code.
#[cfg(not(target_arch = "wasm32"))]
use tacenta_directory::{decode_dir_request, encode_dir_response};
use tacenta_relay::DeviceAddr;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Verifies a registrant's proof of possession. The transport owns the
/// register/lookup protocol but delegates the cryptography — a fresh
/// challenge, and checking a signature over it against the *submitted*
/// identity key — to this trait, so the transport itself stays free of any
/// cryptographic dependency (the sibling of `Authenticator` for relay
/// connections).
pub trait Possession: Send + Sync + 'static {
    /// A fresh, unpredictable challenge for one connection.
    fn challenge(&self) -> Vec<u8>;

    /// Whether `signature` over `challenge` proves possession of the
    /// private key for `identity`. `false` refuses the registration.
    fn verify(&self, identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool;
}

/// How the unauthenticated directory `Register` path admits *new* raw handles
/// (registration admission control). Re-confirms of an already-bound handle
/// are unaffected by either mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RegistrationPolicy {
    /// Anyone may self-register a new raw handle, subject to the per-source
    /// throttle (layer 1, decision 0079). The default.
    #[default]
    Open,
    /// Unauthenticated self-registration of a *new* raw handle is closed
    /// ([`DirResponse::RegistrationClosed`]); handles are obtained only through
    /// authenticated account provisioning (layer 2, decision 0080). Account
    /// provisioning calls `Directory::register` directly, not through this path,
    /// so it is unaffected.
    AccountsOnly,
}

/// A directory and its possession verifier, shared across connections.
/// The directory is held behind a shared lock so the *same* store can be
/// read by a co-located relay server's authenticator (the directory
/// service writes registrations; the relay reads identities to
/// authenticate connections). It is locked only for the synchronous
/// register/lookup — no lock is ever held across an `await`.
pub struct DirServer<P: Possession> {
    directory: Arc<Mutex<Directory>>,
    possession: P,
    /// Per-source throttle on *new* handle registrations (layer 1, decision
    /// 0079). Consulted only for a new binding under [`RegistrationPolicy::Open`],
    /// so a returning client re-confirming its own handle is never throttled.
    reg_limiter: Mutex<RegistrationLimiter>,
    /// How new raw-handle registration is admitted (layer 2, decision 0080).
    registration_policy: RegistrationPolicy,
}

/// Wrap a shared directory and a possession verifier for sharing across
/// connections, with the default registration throttle
/// ([`DEFAULT_MAX_PER_WINDOW`] new handles per source per hour) and the default
/// [`RegistrationPolicy::Open`]. Pass the same `Arc<Mutex<Directory>>` to a relay
/// server's authenticator to co-locate the two services over one store.
pub fn dir_server<P: Possession>(
    directory: Arc<Mutex<Directory>>,
    possession: P,
) -> Arc<DirServer<P>> {
    dir_server_with_limit(directory, possession, DEFAULT_MAX_PER_WINDOW)
}

/// Like [`dir_server`] but with an explicit registration ceiling
/// (`TACENTA_REGISTRATION_MAX_PER_HOUR`, decision 0079) and the default
/// [`RegistrationPolicy::Open`].
pub fn dir_server_with_limit<P: Possession>(
    directory: Arc<Mutex<Directory>>,
    possession: P,
    max_registrations_per_hour: usize,
) -> Arc<DirServer<P>> {
    dir_server_gated(
        directory,
        possession,
        max_registrations_per_hour,
        RegistrationPolicy::Open,
    )
}

/// Like [`dir_server_with_limit`] but with an explicit [`RegistrationPolicy`] — the
/// deployment sets this from `TACENTA_REGISTRATION_POLICY` (decision 0080). The
/// ceiling still applies to new registrations under `Open`; under `AccountsOnly`
/// new raw-handle registration is closed and the ceiling is moot.
pub fn dir_server_gated<P: Possession>(
    directory: Arc<Mutex<Directory>>,
    possession: P,
    max_registrations_per_hour: usize,
    registration_policy: RegistrationPolicy,
) -> Arc<DirServer<P>> {
    Arc::new(DirServer {
        directory,
        possession,
        reg_limiter: Mutex::new(RegistrationLimiter::with_max(max_registrations_per_hour)),
        registration_policy,
    })
}

/// Is this handle in the namespace reserved for account provisioning?
///
/// **Why `/` and why here.** `tacenta_accounts::handle` builds every account
/// handle as `format!("{tenant}/{username}")`, so `/` is exactly the marker
/// that separates the account namespace from raw handles. Reserving it makes
/// the two namespaces disjoint by construction rather than by convention.
///
/// This lives on the *transport* path and not in `Directory::register`, which
/// is deliberate and is the whole design: `AccountProvisioner` calls
/// `Directory::register` directly with a handle derived from a validated
/// session, and must keep being allowed to bind `tenant/user`. It is the
/// unauthenticated request path that may not.
///
/// Without it, an unauthenticated caller could bind any unclaimed handle
/// including an account-shaped one; `lookup` would then return their key to
/// senders, and trust on first use would lock the rightful owner out
/// permanently, provisioning included.
fn is_reserved_handle(user: &str) -> bool {
    user.contains('/')
}

impl<P: Possession> DirServer<P> {
    /// Dispatch one request against the connection's `challenge`. A
    /// `Register` proves possession (injected crypto) before the directory
    /// applies trust on first use; a `Lookup` returns public material.
    fn handle(&self, challenge: &[u8], source: &str, request: DirRequest) -> DirResponse {
        match request {
            DirRequest::Register {
                device,
                identity,
                bundle,
                signature,
            } => {
                // **The handle namespace check, and it comes before the
                // signature check on purpose** -- a caller who may not bind this
                // handle at all should not be told whether their signature was
                // acceptable.
                if is_reserved_handle(&device.user) {
                    return DirResponse::ReservedHandle;
                }
                if !self.possession.verify(&identity, challenge, &signature) {
                    return DirResponse::PossessionFailed;
                }
                let mut directory = self.directory.lock().expect("directory mutex poisoned");
                // Registration admission control . A re-confirm of a handle
                // this caller already holds is never gated — only a *new* binding
                // is. Both checks are after possession, so a caller who cannot
                // prove the key learns nothing about the policy or the throttle.
                if !directory.contains_device(&device) {
                    match self.registration_policy {
                        // Layer 2 (decision 0080): unauthenticated self-registration
                        // of a new raw handle is closed; use account provisioning.
                        RegistrationPolicy::AccountsOnly => {
                            return DirResponse::RegistrationClosed;
                        }
                        // Layer 1 (decision 0079): per-source throttle. A refused
                        // new registration is not recorded.
                        RegistrationPolicy::Open => {
                            if self
                                .reg_limiter
                                .lock()
                                .expect("registration limiter poisoned")
                                .over_limit(source)
                            {
                                return DirResponse::RateLimited;
                            }
                        }
                    }
                }
                directory.register(&device, identity, bundle).into()
            }
            DirRequest::DepositPrekeys {
                device,
                identity,
                bundles,
                signature,
            } => {
                // Same proof `Register` demands, and for the same reason: the
                // pool a peer is served from must be stocked only by the
                // device it belongs to.
                if !self.possession.verify(&identity, challenge, &signature) {
                    return DirResponse::PossessionFailed;
                }
                self.directory
                    .lock()
                    .expect("directory mutex poisoned")
                    .deposit_prekeys(&device, &identity, bundles)
                    .into()
            }
            DirRequest::Lookup { device } => {
                match self
                    .directory
                    .lock()
                    .expect("directory mutex poisoned")
                    .lookup(&device)
                {
                    Some((identity, bundle)) => DirResponse::Found {
                        identity: identity.to_vec(),
                        bundle: bundle.to_vec(),
                    },
                    None => DirResponse::NotFound,
                }
            }
            DirRequest::Rotate {
                device,
                new_identity,
                new_bundle,
                possession_sig,
                rotation_sig,
            } => {
                // Possession of the new key needs no directory state.
                if !self
                    .possession
                    .verify(&new_identity, challenge, &possession_sig)
                {
                    return DirResponse::PossessionFailed;
                }
                // Read the current binding, verify the authorization, and
                // rotate under one lock, so the binding cannot change between
                // the check and the replacement. The verify is synchronous CPU work;
                // no lock is held across an await.
                let mut dir = self.directory.lock().expect("directory mutex poisoned");
                let Some(current) = dir.identity(&device).map(<[u8]>::to_vec) else {
                    return DirResponse::Unregistered;
                };
                let mut statement = challenge.to_vec();
                statement.extend_from_slice(&new_identity);
                if !self.possession.verify(&current, &statement, &rotation_sig) {
                    return DirResponse::Unauthorized;
                }
                dir.rotate(&device, new_identity, new_bundle).into()
            }
            DirRequest::SetRecovery {
                device,
                recovery,
                signature,
            } => {
                // Attaching a recovery key is authorized by the currently
                // bound identity key, checked and applied under one lock.
                let mut dir = self.directory.lock().expect("directory mutex poisoned");
                let Some(current) = dir.identity(&device).map(<[u8]>::to_vec) else {
                    return DirResponse::Unregistered;
                };
                if !self.possession.verify(&current, challenge, &signature) {
                    return DirResponse::Unauthorized;
                }
                dir.set_recovery(&device, recovery).into()
            }
            DirRequest::Recover {
                device,
                new_identity,
                new_bundle,
                possession_sig,
                recovery_sig,
            } => {
                // Possession of the new key needs no directory state.
                if !self
                    .possession
                    .verify(&new_identity, challenge, &possession_sig)
                {
                    return DirResponse::PossessionFailed;
                }
                // Authorize against the *recovery* key (not the lost identity
                // key), then rotate — read, verify, and swap under one lock.
                let mut dir = self.directory.lock().expect("directory mutex poisoned");
                let Some(recovery) = dir.recovery_key(&device).map(<[u8]>::to_vec) else {
                    return DirResponse::NoRecovery;
                };
                let mut statement = challenge.to_vec();
                statement.extend_from_slice(&new_identity);
                if !self.possession.verify(&recovery, &statement, &recovery_sig) {
                    return DirResponse::Unauthorized;
                }
                dir.rotate(&device, new_identity, new_bundle).into()
            }
            DirRequest::Witness {
                device,
                generation,
                signature,
            } => {
                // Possession is proven against the *bound* identity, read under
                // the same lock the witness advances, so only the device that
                // owns the binding can move its own rollback anchor (0078).
                let mut dir = self.directory.lock().expect("directory mutex poisoned");
                let Some(current) = dir.identity(&device).map(<[u8]>::to_vec) else {
                    return DirResponse::Unregistered;
                };
                if !self.possession.verify(&current, challenge, &signature) {
                    return DirResponse::PossessionFailed;
                }
                dir.witness(&device, generation).into()
            }
        }
    }
}

/// Serve one directory connection: issue a challenge, then answer
/// register/lookup requests until the client disconnects. Generic over the
/// byte stream, so it serves plain TCP or a TLS stream over TCP identically.
#[cfg(not(target_arch = "wasm32"))]
async fn serve_dir_connection<S, P>(
    mut stream: S,
    source: String,
    server: Arc<DirServer<P>>,
    idle: std::time::Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    P: Possession,
{
    let challenge = server.possession.challenge();
    write_frame(&mut stream, &challenge).await?;
    loop {
        // A client that connects and falls silent is closed.
        let Some(frame) = crate::read_frame_within(&mut stream, idle).await? else {
            return Ok(());
        };
        let Some(request) = decode_dir_request(&frame) else {
            return Ok(());
        };
        let response = server.handle(&challenge, &source, request);
        write_frame(&mut stream, &encode_dir_response(&response)).await?;
    }
}

/// Accept directory connections forever, serving each against the shared
/// server. Returns only on a fatal accept error.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_directory<P: Possession>(
    listener: TcpListener,
    server: Arc<DirServer<P>>,
) -> std::io::Result<()> {
    serve_directory_with_limits(listener, server, crate::ServeLimits::default()).await
}

/// [`serve_directory`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_directory_with_limits<P: Possession>(
    listener: TcpListener,
    server: Arc<DirServer<P>>,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |stream, peer| {
        let source = peer.ip().to_string();
        let server = server.clone();
        async move {
            let _ = serve_dir_connection(stream, source, server, limits.idle).await;
        }
    })
    .await
}

/// Like [`serve_directory`], but each accepted connection is wrapped in TLS
/// before the framed protocol runs. A failed handshake ends that connection.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_directory_tls<P: Possession>(
    listener: TcpListener,
    server: Arc<DirServer<P>>,
    tls: crate::ServerTls,
) -> std::io::Result<()> {
    serve_directory_tls_with_limits(listener, server, tls, crate::ServeLimits::default()).await
}

/// [`serve_directory_tls`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_directory_tls_with_limits<P: Possession>(
    listener: TcpListener,
    server: Arc<DirServer<P>>,
    tls: crate::ServerTls,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |tcp, peer| {
        let source = peer.ip().to_string();
        let server = server.clone();
        let acceptor = tls.acceptor.clone();
        async move {
            if let Ok(stream) = acceptor.accept(tcp).await {
                let _ = serve_dir_connection(stream, source, server, limits.idle).await;
            }
        }
    })
    .await
}

/// A client connection to a directory server. The connection's challenge
/// (issued once, on connect) is what a `register` signs. The stream halves
/// are boxed so the connection is agnostic to the underlying transport
/// (plain TCP, TLS over TCP, or the WebSocket carriage).
pub struct DirConnection {
    read: Box<dyn AsyncRead + Unpin + Send + Sync>,
    write: Box<dyn AsyncWrite + Unpin + Send + Sync>,
    challenge: Vec<u8>,
}

impl DirConnection {
    /// Connect over TCP and receive the connection challenge.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<DirConnection> {
        let stream = TcpStream::connect(addr).await?;
        DirConnection::establish(stream).await
    }

    /// Connect over TLS to a server presenting `server_name`, then receive
    /// the connection challenge. `tls` decides which server certificate to
    /// trust.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &crate::ClientTls,
    ) -> std::io::Result<DirConnection> {
        let tcp = TcpStream::connect(addr).await?;
        let stream = tls.wrap(server_name, tcp).await?;
        DirConnection::establish(stream).await
    }

    /// Receive the connection challenge over an already-connected `stream`.
    /// The transport layer — TCP, or TLS over TCP — is the caller's; a TLS
    /// client wraps a stream and calls this.
    pub async fn establish<S>(mut stream: S) -> std::io::Result<DirConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let challenge = read_frame(&mut stream).await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no challenge")
        })?;
        let (read, write) = tokio::io::split(stream);
        Ok(DirConnection {
            read: Box::new(read),
            write: Box::new(write),
            challenge,
        })
    }

    /// Publish `identity` and `bundle` for `device`. `sign` signs the
    /// connection challenge with the identity's private key (the caller
    /// owns the identity key and the signing crypto). Returns the server's
    /// outcome — `Registered` / `Refreshed` / `Rejected` / `PossessionFailed`.
    pub async fn register(
        &mut self,
        device: &DeviceAddr,
        identity: Vec<u8>,
        bundle: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let signature = sign(&self.challenge);
        let request = encode_dir_request(&DirRequest::Register {
            device: device.clone(),
            identity,
            bundle,
            signature,
        });
        self.exchange(&request).await
    }

    /// Stock the device's one-time bundle pool (decision 0074).
    ///
    /// Sent after `register`, and again whenever the pool runs low. Each
    /// bundle carries a one-time prekey the directory hands to exactly one
    /// peer; when the pool empties, lookups fall back to the multi-use bundle
    /// registered above.
    ///
    /// Signs the same challenge `register` does, because the directory has to
    /// know the batch came from the device whose pool it stocks.
    pub async fn deposit_prekeys(
        &mut self,
        device: &DeviceAddr,
        identity: Vec<u8>,
        bundles: Vec<Vec<u8>>,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let signature = sign(&self.challenge);
        let request = encode_dir_request(&DirRequest::DepositPrekeys {
            device: device.clone(),
            identity,
            bundles,
            signature,
        });
        self.exchange(&request).await
    }

    /// Present `device`'s current persisted-state `generation` for the
    /// directory to witness (decision 0078). `sign` signs the challenge
    /// with the device's identity key — the server verifies against the bound
    /// key, so no identity is sent. Returns `Fresh`, `RolledBack`, or
    /// `Unregistered`/`PossessionFailed`.
    pub async fn witness(
        &mut self,
        device: &DeviceAddr,
        generation: u64,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let signature = sign(&self.challenge);
        let request = encode_dir_request(&DirRequest::Witness {
            device: device.clone(),
            generation,
            signature,
        });
        self.exchange(&request).await
    }

    /// Look up a device's published identity key and prekey bundle.
    /// Returns `Found { .. }` or `NotFound`.
    pub async fn lookup(&mut self, device: &DeviceAddr) -> std::io::Result<DirResponse> {
        let request = encode_dir_request(&DirRequest::Lookup {
            device: device.clone(),
        });
        self.exchange(&request).await
    }

    /// Rotate `device`'s bound identity to `new_identity` + `new_bundle`
    /// (decision record 0024). `sign_possession` signs the connection
    /// challenge with the *new* key; `sign_rotation` signs `challenge ++
    /// new_identity` with the *currently bound* key, authorizing the change.
    /// Returns `Rotated` / `Unauthorized` / `Unregistered` / `PossessionFailed`.
    pub async fn rotate(
        &mut self,
        device: &DeviceAddr,
        new_identity: Vec<u8>,
        new_bundle: Vec<u8>,
        sign_possession: impl FnOnce(&[u8]) -> Vec<u8>,
        sign_rotation: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let possession_sig = sign_possession(&self.challenge);
        let mut statement = self.challenge.clone();
        statement.extend_from_slice(&new_identity);
        let rotation_sig = sign_rotation(&statement);
        let request = encode_dir_request(&DirRequest::Rotate {
            device: device.clone(),
            new_identity,
            new_bundle,
            possession_sig,
            rotation_sig,
        });
        self.exchange(&request).await
    }

    /// Attach a `recovery` key to `device` (decision record 0025).
    /// `sign` signs the connection challenge with the *currently bound*
    /// identity key, authorizing the change. Returns `RecoverySet` /
    /// `Unauthorized` / `Unregistered`.
    pub async fn set_recovery(
        &mut self,
        device: &DeviceAddr,
        recovery: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let signature = sign(&self.challenge);
        let request = encode_dir_request(&DirRequest::SetRecovery {
            device: device.clone(),
            recovery,
            signature,
        });
        self.exchange(&request).await
    }

    /// Recover `device` to `new_identity` + `new_bundle` when its identity
    /// key is lost. `sign_possession` signs the challenge with the *new*
    /// key; `sign_recovery` signs `challenge ++ new_identity` with the
    /// *recovery* key. Returns `Rotated` / `Unauthorized` / `NoRecovery` /
    /// `PossessionFailed`.
    pub async fn recover(
        &mut self,
        device: &DeviceAddr,
        new_identity: Vec<u8>,
        new_bundle: Vec<u8>,
        sign_possession: impl FnOnce(&[u8]) -> Vec<u8>,
        sign_recovery: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<DirResponse> {
        let possession_sig = sign_possession(&self.challenge);
        let mut statement = self.challenge.clone();
        statement.extend_from_slice(&new_identity);
        let recovery_sig = sign_recovery(&statement);
        let request = encode_dir_request(&DirRequest::Recover {
            device: device.clone(),
            new_identity,
            new_bundle,
            possession_sig,
            recovery_sig,
        });
        self.exchange(&request).await
    }

    /// Write a request frame and read the decoded response.
    async fn exchange(&mut self, request: &[u8]) -> std::io::Result<DirResponse> {
        write_frame(&mut self.write, request).await?;
        let frame = read_frame(&mut self.read)
            .await?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response"))?;
        decode_dir_response(&frame).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed response")
        })
    }
}

#[cfg(test)]
mod ra1_tests {
    //! Registration admission control (decision 0079): the directory
    //! throttles *new* handle registrations per source, never re-confirms, and
    //! checks the throttle only after possession.
    use super::*;
    use tacenta_directory::Directory;

    /// A possession verifier whose answer is fixed, so a test can drive the
    /// register path with or without a valid proof.
    struct TestPoss {
        ok: bool,
    }
    impl Possession for TestPoss {
        fn challenge(&self) -> Vec<u8> {
            vec![0u8; 16]
        }
        fn verify(&self, _identity: &[u8], _challenge: &[u8], _signature: &[u8]) -> bool {
            self.ok
        }
    }

    fn register(user: &str) -> DirRequest {
        DirRequest::Register {
            device: DeviceAddr::new(user, 1),
            identity: format!("id-{user}").into_bytes(),
            bundle: b"bundle".to_vec(),
            signature: b"sig".to_vec(),
        }
    }

    fn server(max: usize, ok: bool) -> Arc<DirServer<TestPoss>> {
        dir_server_with_limit(Arc::new(Mutex::new(Directory::new())), TestPoss { ok }, max)
    }

    /// New registrations from one source are allowed up to the ceiling, then
    /// refused as `RateLimited` — while a *different* source is unaffected.
    #[test]
    fn new_registrations_are_throttled_per_source() {
        let s = server(2, true);
        let ch = vec![0u8; 16];
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::Registered
        );
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("b")),
            DirResponse::Registered
        );
        // Third *new* handle from the same source is over the ceiling.
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("c")),
            DirResponse::RateLimited
        );
        // A different source has its own budget; the same handle it refused
        // above registers fine here.
        assert_eq!(
            s.handle(&ch, "2.2.2.2", register("c")),
            DirResponse::Registered
        );
    }

    /// A returning client re-confirming a handle it already holds is never
    /// throttled, even when the source is over the ceiling for *new* handles.
    #[test]
    fn re_confirms_are_never_throttled() {
        let s = server(1, true);
        let ch = vec![0u8; 16];
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::Registered
        );
        // The source is now at its new-handle ceiling: a new handle is refused.
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("b")),
            DirResponse::RateLimited
        );
        // But re-confirming the handle it already holds (same key) still works.
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::Refreshed
        );
    }

    /// The throttle is checked after possession, so a caller who cannot prove
    /// the key gets `PossessionFailed` and learns nothing about the limit — and
    /// a failed proof never consumes a registration slot.
    #[test]
    fn possession_is_checked_before_the_throttle() {
        let s = server(1, false);
        let ch = vec![0u8; 16];
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::PossessionFailed
        );
        // A second failing attempt is still PossessionFailed, not RateLimited:
        // the ceiling of 1 was not consumed by the rejected attempt.
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::PossessionFailed
        );
    }

    // ---- layer 2: account-gated registration (decision 0080) ----

    /// Under `AccountsOnly`, a *new* raw-handle self-registration is closed —
    /// nothing is bound — regardless of source or ceiling.
    #[test]
    fn accounts_only_closes_a_new_raw_registration() {
        let dir = Arc::new(Mutex::new(Directory::new()));
        let s = dir_server_gated(
            dir.clone(),
            TestPoss { ok: true },
            20,
            RegistrationPolicy::AccountsOnly,
        );
        let ch = vec![0u8; 16];
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::RegistrationClosed
        );
        assert!(
            !dir.lock()
                .unwrap()
                .contains_device(&DeviceAddr::new("a", 1)),
            "a closed registration binds nothing"
        );
    }

    /// Under `AccountsOnly`, a returning client re-confirming a handle it already
    /// holds still succeeds — the gate is only on *new* bindings, so provisioning
    /// (which binds directly) and returning clients are unaffected.
    #[test]
    fn accounts_only_still_allows_a_re_confirm() {
        let dir = Arc::new(Mutex::new(Directory::new()));
        // Seed a raw-handle binding directly, as account provisioning would.
        dir.lock().unwrap().register(
            &DeviceAddr::new("a", 1),
            b"id-a".to_vec(),
            b"bundle".to_vec(),
        );
        let s = dir_server_gated(
            dir.clone(),
            TestPoss { ok: true },
            20,
            RegistrationPolicy::AccountsOnly,
        );
        let ch = vec![0u8; 16];
        // Same key, new bundle → a refresh of the existing binding, not closed.
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::Refreshed
        );
    }

    /// Possession is still checked before the policy, so a caller who cannot prove
    /// the key gets `PossessionFailed`, not `RegistrationClosed`.
    #[test]
    fn accounts_only_checks_possession_first() {
        let dir = Arc::new(Mutex::new(Directory::new()));
        let s = dir_server_gated(
            dir,
            TestPoss { ok: false },
            20,
            RegistrationPolicy::AccountsOnly,
        );
        let ch = vec![0u8; 16];
        assert_eq!(
            s.handle(&ch, "192.0.2.1", register("a")),
            DirResponse::PossessionFailed
        );
    }
}
