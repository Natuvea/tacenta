//! A backend-agnostic account store: the in-memory store (snapshot-persisted)
//! or the Postgres store, behind one async surface, so the server can run on
//! either without the transport or the provisioner knowing which.
//!
//! The in-memory backend is synchronous under a lock; the async methods here
//! wrap it (they never hold the lock across an await). The Postgres backend is
//! naturally async. Errors unify to [`StoreError`].

use std::sync::Mutex;

use crate::{
    Accounts, ApiKey, ApiKeyInfo, AuthError, SessionToken, SignupError, Tenant, TenantId, User,
};

/// What can go wrong at the store: a domain refusal (the same the in-memory
/// store returns) or a backend failure (only a database backend produces
/// these — the in-memory one cannot fail infrastructurally).
#[derive(Debug)]
pub enum StoreError {
    /// A signup was refused.
    Signup(SignupError),
    /// Authentication failed.
    Auth(AuthError),
    /// The backend (a database) failed.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Signup(e) => write!(f, "signup refused: {e:?}"),
            StoreError::Auth(e) => write!(f, "authentication failed: {e:?}"),
            StoreError::Backend(e) => write!(f, "store backend error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(feature = "postgres")]
impl From<crate::pg::PgError> for StoreError {
    fn from(e: crate::pg::PgError) -> StoreError {
        match e {
            crate::pg::PgError::Database(db) => StoreError::Backend(db.to_string()),
            crate::pg::PgError::Signup(s) => StoreError::Signup(s),
            crate::pg::PgError::Auth(a) => StoreError::Auth(a),
        }
    }
}

/// The account store the server runs on — either in memory or PostgreSQL.
pub enum AccountStore {
    /// The in-memory store, persisted by whole-state snapshot. Boxed so the
    /// (much larger) in-memory maps do not inflate the enum's size against the
    /// pool-sized Postgres variant.
    Memory(Box<Mutex<Accounts>>),
    /// The PostgreSQL store, durable in the database.
    #[cfg(feature = "postgres")]
    Postgres(crate::pg::PgAccounts),
}

impl AccountStore {
    /// An in-memory backend around `accounts`.
    pub fn memory(accounts: Accounts) -> AccountStore {
        AccountStore::Memory(Box::new(Mutex::new(accounts)))
    }

    /// A PostgreSQL backend.
    #[cfg(feature = "postgres")]
    pub fn postgres(store: crate::pg::PgAccounts) -> AccountStore {
        AccountStore::Postgres(store)
    }

    /// Sign up a tenant.
    pub async fn sign_up_tenant(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(Tenant, ApiKey), StoreError> {
        match self {
            AccountStore::Memory(m) => m
                .lock()
                .expect("accounts mutex poisoned")
                .sign_up_tenant(username, email, password)
                .map_err(StoreError::Signup),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .sign_up_tenant(username, email, password)
                .await
                .map_err(StoreError::from),
        }
    }

    /// Sign up a user within a tenant.
    pub async fn sign_up_user(
        &self,
        tenant: &TenantId,
        username: &str,
        password: &str,
    ) -> Result<User, StoreError> {
        match self {
            AccountStore::Memory(m) => m
                .lock()
                .expect("accounts mutex poisoned")
                .sign_up_user(tenant, username, password)
                .map_err(StoreError::Signup),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .sign_up_user(tenant, username, password)
                .await
                .map_err(StoreError::from),
        }
    }

    /// Authenticate a user and issue a session token.
    pub async fn sign_in(
        &self,
        tenant: &TenantId,
        identifier: &str,
        password: &str,
    ) -> Result<(User, SessionToken), StoreError> {
        match self {
            AccountStore::Memory(m) => m
                .lock()
                .expect("accounts mutex poisoned")
                .sign_in(tenant, identifier, password)
                .map_err(StoreError::Auth),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .sign_in(tenant, identifier, password)
                .await
                .map_err(StoreError::from),
        }
    }

    /// The tenant an API key belongs to, if any.
    pub async fn tenant_by_api_key(&self, api_key: &str) -> Result<Option<TenantId>, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .tenant_by_api_key(api_key)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => {
                s.tenant_by_api_key(api_key).await.map_err(StoreError::from)
            }
        }
    }

    /// Authenticate a tenant by its username or email plus password — the gate
    /// in front of key management (decision record 0048).
    pub async fn authenticate_tenant(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<TenantId, StoreError> {
        match self {
            AccountStore::Memory(m) => m
                .lock()
                .expect("accounts mutex poisoned")
                .authenticate_tenant(identifier, password)
                .map_err(StoreError::Auth),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .authenticate_tenant(identifier, password)
                .await
                .map_err(StoreError::from),
        }
    }

    /// Mint an additional API key for a tenant, returned once.
    pub async fn create_api_key(
        &self,
        tenant: &TenantId,
        label: Option<String>,
    ) -> Result<ApiKey, StoreError> {
        match self {
            AccountStore::Memory(m) => m
                .lock()
                .expect("accounts mutex poisoned")
                .create_api_key(tenant, label)
                .map_err(StoreError::Auth),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .create_api_key(tenant, label.as_deref())
                .await
                .map_err(StoreError::from),
        }
    }

    /// The API keys a tenant holds (prefix, label, creation time), never the
    /// secret.
    pub async fn list_api_keys(&self, tenant: &TenantId) -> Result<Vec<ApiKeyInfo>, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .list_api_keys(tenant)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s.list_api_keys(tenant).await.map_err(StoreError::from),
        }
    }

    /// Revoke a tenant's API key by prefix. Returns whether one was removed.
    pub async fn revoke_api_key(
        &self,
        tenant: &TenantId,
        prefix: &str,
    ) -> Result<bool, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .revoke_api_key(tenant, prefix)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .revoke_api_key(tenant, prefix)
                .await
                .map_err(StoreError::from),
        }
    }

    /// The user a session token authorises, if any.
    pub async fn validate_session(
        &self,
        token: &str,
    ) -> Result<Option<(TenantId, String)>, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .validate_session(token)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s.validate_session(token).await.map_err(StoreError::from),
        }
    }

    /// Revoke a single session before its TTL. Returns whether one was removed.
    pub async fn revoke_session(&self, token: &str) -> Result<bool, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .revoke_session(token)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s.revoke_session(token).await.map_err(StoreError::from),
        }
    }

    /// Revoke every session for a user. Returns how many were removed.
    pub async fn revoke_user_sessions(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<usize, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .revoke_user_sessions(tenant, username)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .revoke_user_sessions(tenant, username)
                .await
                .map(|n| n as usize)
                .map_err(StoreError::from),
        }
    }

    /// Drop expired sessions (memory hygiene). Returns how many were removed.
    pub async fn sweep_expired_sessions(&self) -> Result<usize, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .sweep_expired_sessions()),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s
                .sweep_expired_sessions()
                .await
                .map(|n| n as usize)
                .map_err(StoreError::from),
        }
    }

    /// The directory handle for a `(tenant, username)`, if the tenant exists.
    pub async fn handle(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<String>, StoreError> {
        match self {
            AccountStore::Memory(m) => Ok(m
                .lock()
                .expect("accounts mutex poisoned")
                .handle(tenant, username)),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(s) => s.handle(tenant, username).await.map_err(StoreError::from),
        }
    }

    /// A whole-state snapshot for the snapshot-persisted in-memory backend, or
    /// `None` for a durable backend (Postgres persists itself, so the server
    /// writes no snapshot for it).
    pub fn snapshot(&self) -> Option<Vec<u8>> {
        match self {
            AccountStore::Memory(m) => Some(m.lock().expect("accounts mutex poisoned").snapshot()),
            #[cfg(feature = "postgres")]
            AccountStore::Postgres(_) => None,
        }
    }
}
