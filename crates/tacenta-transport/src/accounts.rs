//! A TCP transport for the account service: sign up a tenant or user, or sign
//! in, over a socket.
//!
//! Unlike the directory, there is no possession challenge — account operations
//! authenticate with a password (and, for tenant-scoped operations, a tenant
//! API key), not with a proof of possession of an identity key. So a
//! connection carries no per-connection challenge; it is plain
//! request/response. The server wraps the crypto-free [`Accounts`] store, which
//! hashes passwords with argon2id on arrival.
//!
//! The requests carry **plaintext passwords and API keys**, so a real
//! deployment serves this over TLS ([`serve_accounts_tls`]), exactly as the
//! directory does.

use crate::{read_frame, write_frame};
use std::sync::Arc;
use tacenta_accounts::{
    AccountRequest, AccountResponse, AccountStore, AuthError, StoreError, decode_account_response,
    encode_account_request,
};
// Used only by the native-only connection-serving code.
#[cfg(not(target_arch = "wasm32"))]
use tacenta_accounts::{decode_account_request, encode_account_response};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// An account store shared across connections. Backend-agnostic: it drives an
/// [`AccountStore`], which is in-memory or PostgreSQL.
pub struct AccountServer {
    store: Arc<AccountStore>,
}

/// Wrap a shared account store for serving across connections.
pub fn account_server(store: Arc<AccountStore>) -> Arc<AccountServer> {
    Arc::new(AccountServer { store })
}

impl AccountServer {
    /// Handle one account request against the store.
    async fn handle(&self, request: AccountRequest) -> AccountResponse {
        match request {
            AccountRequest::SignUpTenant {
                username,
                email,
                password,
            } => match self
                .store
                .sign_up_tenant(&username, &email, &password)
                .await
            {
                Ok((tenant, api_key)) => AccountResponse::TenantCreated {
                    tenant_id: tenant.id.as_str().to_owned(),
                    api_key: api_key.as_str().to_owned(),
                },
                Err(StoreError::Signup(e)) => refuse_signup(e),
                Err(_) => AccountResponse::ServerError,
            },
            AccountRequest::SignUpUser {
                api_key,
                username,
                password,
            } => {
                let tenant = match self.store.tenant_by_api_key(&api_key).await {
                    Ok(Some(tenant)) => tenant,
                    Ok(None) => return AccountResponse::UnknownTenant,
                    Err(_) => return AccountResponse::ServerError,
                };
                match self.store.sign_up_user(&tenant, &username, &password).await {
                    Ok(user) => AccountResponse::UserCreated {
                        username: user.username,
                    },
                    Err(StoreError::Signup(e)) => refuse_signup(e),
                    Err(_) => AccountResponse::ServerError,
                }
            }
            AccountRequest::SignIn {
                api_key,
                identifier,
                password,
            } => {
                let tenant = match self.store.tenant_by_api_key(&api_key).await {
                    Ok(Some(tenant)) => tenant,
                    Ok(None) => return AccountResponse::UnknownTenant,
                    Err(_) => return AccountResponse::ServerError,
                };
                match self.store.sign_in(&tenant, &identifier, &password).await {
                    Ok((user, token)) => AccountResponse::SignedIn {
                        username: user.username,
                        token: token.as_str().to_owned(),
                    },
                    // The throttle is its own answer, so a client can back off
                    // rather than re-prompt; it is not an existence oracle
                    // (unknown identifiers are counted too).
                    Err(StoreError::Auth(AuthError::RateLimited)) => AccountResponse::RateLimited,
                    // Coarse — never distinguishes wrong password from no such
                    // user, and never leaks it as an unknown-tenant either.
                    Err(StoreError::Auth(_)) => AccountResponse::SignInRefused,
                    Err(_) => AccountResponse::ServerError,
                }
            }
        }
    }
}

fn refuse_signup(error: tacenta_accounts::SignupError) -> AccountResponse {
    match error.reason() {
        Some(reason) => AccountResponse::SignupRefused { reason },
        None => AccountResponse::UnknownTenant,
    }
}

/// Serve one account connection: answer requests until the client
/// disconnects. Generic over the byte stream, so it serves plain TCP or a TLS
/// stream over TCP identically.
#[cfg(not(target_arch = "wasm32"))]
async fn serve_account_connection<S>(
    mut stream: S,
    server: Arc<AccountServer>,
    idle: std::time::Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        // A client that connects and falls silent is closed.
        let Some(frame) = crate::read_frame_within(&mut stream, idle).await? else {
            return Ok(());
        };
        let Some(request) = decode_account_request(&frame) else {
            return Ok(());
        };
        let response = server.handle(request).await;
        write_frame(&mut stream, &encode_account_response(&response)).await?;
    }
}

/// Accept account connections forever, serving each against the shared server.
/// Returns only on a fatal accept error.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_accounts(
    listener: TcpListener,
    server: Arc<AccountServer>,
) -> std::io::Result<()> {
    serve_accounts_with_limits(listener, server, crate::ServeLimits::default()).await
}

/// [`serve_accounts`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_accounts_with_limits(
    listener: TcpListener,
    server: Arc<AccountServer>,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |stream, _peer| {
        let server = server.clone();
        async move {
            let _ = serve_account_connection(stream, server, limits.idle).await;
        }
    })
    .await
}

/// Like [`serve_accounts`], but each connection is wrapped in TLS before the
/// framed protocol runs. A failed handshake ends that connection. This is the
/// path a real deployment uses, since account requests carry plaintext
/// passwords.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_accounts_tls(
    listener: TcpListener,
    server: Arc<AccountServer>,
    tls: crate::ServerTls,
) -> std::io::Result<()> {
    serve_accounts_tls_with_limits(listener, server, tls, crate::ServeLimits::default()).await
}

/// [`serve_accounts_tls`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_accounts_tls_with_limits(
    listener: TcpListener,
    server: Arc<AccountServer>,
    tls: crate::ServerTls,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |tcp, _peer| {
        let server = server.clone();
        let acceptor = tls.acceptor.clone();
        async move {
            if let Ok(stream) = acceptor.accept(tcp).await {
                let _ = serve_account_connection(stream, server, limits.idle).await;
            }
        }
    })
    .await
}

/// A client connection to an account server. Plain request/response — no
/// per-connection challenge, unlike the directory.
pub struct AccountConnection {
    read: Box<dyn AsyncRead + Unpin + Send + Sync>,
    write: Box<dyn AsyncWrite + Unpin + Send + Sync>,
}

impl AccountConnection {
    /// Connect over TCP.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<AccountConnection> {
        let stream = TcpStream::connect(addr).await?;
        AccountConnection::establish(stream).await
    }

    /// Connect over TLS to a server presenting `server_name`. `tls` decides
    /// which server certificate to trust. This is the path to use in a real
    /// deployment, since the requests carry plaintext passwords.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &crate::ClientTls,
    ) -> std::io::Result<AccountConnection> {
        let tcp = TcpStream::connect(addr).await?;
        let stream = tls.wrap(server_name, tcp).await?;
        AccountConnection::establish(stream).await
    }

    /// Wrap an already-connected `stream`. The transport layer — TCP, or TLS
    /// over TCP — is the caller's.
    pub async fn establish<S>(stream: S) -> std::io::Result<AccountConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (read, write) = tokio::io::split(stream);
        Ok(AccountConnection {
            read: Box::new(read),
            write: Box::new(write),
        })
    }

    async fn exchange(&mut self, request: &AccountRequest) -> std::io::Result<AccountResponse> {
        write_frame(&mut self.write, &encode_account_request(request)).await?;
        let frame = read_frame(&mut self.read)
            .await?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response"))?;
        decode_account_response(&frame).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed response")
        })
    }

    /// Create a new tenant. On success the response carries the tenant id and
    /// its one-time API key.
    pub async fn sign_up_tenant(
        &mut self,
        username: &str,
        email: &str,
        password: &str,
    ) -> std::io::Result<AccountResponse> {
        self.exchange(&AccountRequest::SignUpTenant {
            username: username.to_owned(),
            email: email.to_owned(),
            password: password.to_owned(),
        })
        .await
    }

    /// Create a user within the tenant the `api_key` selects. Users sign up
    /// with a username and password only — no email.
    pub async fn sign_up_user(
        &mut self,
        api_key: &str,
        username: &str,
        password: &str,
    ) -> std::io::Result<AccountResponse> {
        self.exchange(&AccountRequest::SignUpUser {
            api_key: api_key.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        })
        .await
    }

    /// Sign in a user within the tenant the `api_key` selects, by username plus
    /// password.
    pub async fn sign_in(
        &mut self,
        api_key: &str,
        identifier: &str,
        password: &str,
    ) -> std::io::Result<AccountResponse> {
        self.exchange(&AccountRequest::SignIn {
            api_key: api_key.to_owned(),
            identifier: identifier.to_owned(),
            password: password.to_owned(),
        })
        .await
    }
}
