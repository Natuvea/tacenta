//! A PostgreSQL-backed account store (decision records 0030, 0039).
//!
//! [`PgAccounts`] mirrors the in-memory [`Accounts`](crate::Accounts) surface —
//! sign up, authenticate, sign in, validate a session, resolve a handle or an
//! API key — but against a database, so the state is durable and the uniqueness
//! rules are enforced by database constraints rather than in-memory index maps.
//! It reuses the same crypto and validation as the in-memory store (argon2id
//! hashing, the coarse errors, the dummy-verify against timing, the prefixed
//! sortable ids), so the two behave identically where it matters.
//!
//! The queries are runtime `sqlx` (no compile-time database), so the crate
//! builds without a database; only the tests need one.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row as _};

use crate::{
    ApiKey, ApiKeyInfo, AuthError, DeviceInventory, InventoryError, SessionToken, SignupError,
    Tenant, TenantId, User,
    inventory::{
        decode_inventory, encode_link_request, encode_replace_request, encode_revoke_request,
        link_inventory, replace_inventory, revoke_inventory, validate_inventory,
    },
    inventory_tx::{InventoryTx, MutationError, PriorMutation, apply_mutation},
};
use tacenta_core::crypto::groups::inventory::DeviceBinding;

/// What can go wrong against the database: an infrastructure error, or one of
/// the domain refusals the in-memory store also returns.
#[derive(Debug)]
pub enum PgError {
    /// A database or connection error.
    Database(sqlx::Error),
    /// A signup was refused (bad input, or a uniqueness collision the database
    /// reported).
    Signup(SignupError),
    /// Authentication failed.
    Auth(AuthError),
    /// A device-inventory lifecycle transition was refused.
    Inventory(InventoryError),
}

impl std::fmt::Display for PgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgError::Database(e) => write!(f, "database error: {e}"),
            PgError::Signup(e) => write!(f, "signup refused: {e:?}"),
            PgError::Auth(e) => write!(f, "authentication failed: {e:?}"),
            PgError::Inventory(e) => write!(f, "inventory mutation refused: {e:?}"),
        }
    }
}

impl std::error::Error for PgError {}

impl From<sqlx::Error> for PgError {
    fn from(e: sqlx::Error) -> PgError {
        PgError::Database(e)
    }
}

/// Map an insert error to a domain signup error when it is a named uniqueness
/// (or foreign-key) violation; otherwise keep it as a database error.
fn signup_error(error: sqlx::Error) -> PgError {
    if let sqlx::Error::Database(db) = &error {
        if db.is_unique_violation() {
            return match db.constraint() {
                Some("tenants_username_key" | "users_pkey") => {
                    PgError::Signup(SignupError::UsernameTaken)
                }
                // Only tenants have an email; users are unique by username.
                Some("tenants_email_key") => PgError::Signup(SignupError::EmailTaken),
                _ => PgError::Database(error),
            };
        }
        if db.is_foreign_key_violation() {
            return PgError::Signup(SignupError::UnknownTenant);
        }
    }
    PgError::Database(error)
}

/// A PostgreSQL-backed account store.
pub struct PgAccounts {
    pool: PgPool,
}

impl PgAccounts {
    /// Connect a pool to `database_url`.
    pub async fn connect(database_url: &str) -> Result<PgAccounts, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(PgAccounts { pool })
    }

    /// Wrap an existing pool.
    pub fn from_pool(pool: PgPool) -> PgAccounts {
        PgAccounts { pool }
    }

    /// Apply the embedded migrations. Idempotent — safe to call on every start.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await
    }

    /// Remove all data. For tests and dev reset only.
    pub async fn truncate(&self) -> Result<(), sqlx::Error> {
        sqlx::query("truncate tenants, api_keys, users, sessions cascade")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Sign up a tenant. Username and email are unique across all tenants (the
    /// `tenants_username_key` / `tenants_email_key` constraints). Returns the
    /// tenant and its API key.
    pub async fn sign_up_tenant(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(Tenant, ApiKey), PgError> {
        let username = crate::normalize_username(username).map_err(PgError::Signup)?;
        let email = crate::normalize_email(email).map_err(PgError::Signup)?;
        crate::validate_password(password).map_err(PgError::Signup)?;

        let id = crate::id::prefixed("ten");
        let (api_key, api_key_hash) = crate::generate_api_key();
        let password_hash = crate::hash_password(password);

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into tenants (id, username, email, password_hash) values ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(&username)
        .bind(&email)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(signup_error)?;
        sqlx::query("insert into api_keys (key_hash, tenant_id, key_prefix) values ($1, $2, $3)")
            .bind(&api_key_hash[..])
            .bind(&id)
            .bind(api_key.prefix())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok((
            Tenant {
                id: TenantId(id),
                username,
                email,
            },
            api_key,
        ))
    }

    /// Authenticate a tenant by username or email plus password.
    pub async fn authenticate_tenant(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<TenantId, PgError> {
        let key = crate::normalize(identifier);
        let row =
            sqlx::query("select id, password_hash from tenants where username = $1 or email = $1")
                .bind(&key)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some(row) => {
                let id: String = row.get("id");
                let password_hash: String = row.get("password_hash");
                if crate::verify_password(password, &password_hash) {
                    Ok(TenantId(id))
                } else {
                    Err(PgError::Auth(AuthError::InvalidCredentials))
                }
            }
            None => {
                let _ = crate::verify_password(password, crate::dummy_hash());
                Err(PgError::Auth(AuthError::InvalidCredentials))
            }
        }
    }

    /// The tenant an API key belongs to, if any.
    pub async fn tenant_by_api_key(&self, api_key: &str) -> Result<Option<TenantId>, PgError> {
        let hash = crate::sha256(api_key.as_bytes());
        let id: Option<String> =
            sqlx::query_scalar("select tenant_id from api_keys where key_hash = $1")
                .bind(&hash[..])
                .fetch_optional(&self.pool)
                .await?;
        Ok(id.map(TenantId))
    }

    /// Mint an additional API key for a tenant, returned once (only its hash is
    /// stored). This is the rotation primitive (decision record 0048).
    pub async fn create_api_key(
        &self,
        tenant: &TenantId,
        label: Option<&str>,
    ) -> Result<ApiKey, PgError> {
        if !self.tenant_exists(tenant).await? {
            return Err(PgError::Auth(AuthError::UnknownTenant));
        }
        let (api_key, api_key_hash) = crate::generate_api_key();
        sqlx::query(
            "insert into api_keys (key_hash, tenant_id, key_prefix, label) \
             values ($1, $2, $3, $4)",
        )
        .bind(&api_key_hash[..])
        .bind(tenant.as_str())
        .bind(api_key.prefix())
        .bind(label)
        .execute(&self.pool)
        .await?;
        Ok(api_key)
    }

    /// The API keys a tenant holds — prefix, label, and creation time (unix
    /// seconds), never the secret — newest first. Keys created before the
    /// metadata migration have a null prefix, surfaced as an empty string.
    pub async fn list_api_keys(&self, tenant: &TenantId) -> Result<Vec<ApiKeyInfo>, PgError> {
        let rows = sqlx::query(
            "select key_prefix, label, extract(epoch from created_at)::bigint as created_at \
             from api_keys where tenant_id = $1 order by created_at desc, key_prefix",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|row| ApiKeyInfo {
                prefix: row
                    .get::<Option<String>, _>("key_prefix")
                    .unwrap_or_default(),
                label: row.get("label"),
                created_at: row.get::<i64, _>("created_at").max(0) as u64,
            })
            .collect())
    }

    /// Revoke a tenant's API key by prefix, so it stops resolving at once.
    /// Returns whether a row was removed.
    pub async fn revoke_api_key(&self, tenant: &TenantId, prefix: &str) -> Result<bool, PgError> {
        let res = sqlx::query("delete from api_keys where tenant_id = $1 and key_prefix = $2")
            .bind(tenant.as_str())
            .bind(prefix)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Fetch a tenant by id.
    pub async fn tenant(&self, id: &TenantId) -> Result<Option<Tenant>, PgError> {
        let row = sqlx::query("select username, email from tenants where id = $1")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| Tenant {
            id: id.clone(),
            username: row.get("username"),
            email: row.get("email"),
        }))
    }

    /// Sign up a user within a tenant. Username and email are unique within the
    /// tenant (the `users_pkey` / `users_tenant_email_key` constraints).
    pub async fn sign_up_user(
        &self,
        tenant: &TenantId,
        username: &str,
        password: &str,
    ) -> Result<User, PgError> {
        if !self.tenant_exists(tenant).await? {
            return Err(PgError::Signup(SignupError::UnknownTenant));
        }
        let username = crate::normalize_username(username).map_err(PgError::Signup)?;
        crate::validate_password(password).map_err(PgError::Signup)?;
        let password_hash = crate::hash_password(password);

        sqlx::query("insert into users (tenant_id, username, password_hash) values ($1, $2, $3)")
            .bind(tenant.as_str())
            .bind(&username)
            .bind(&password_hash)
            .execute(&self.pool)
            .await
            .map_err(signup_error)?;

        Ok(User {
            tenant: tenant.clone(),
            username,
        })
    }

    /// Authenticate a user within a tenant by username plus password.
    pub async fn authenticate_user(
        &self,
        tenant: &TenantId,
        username: &str,
        password: &str,
    ) -> Result<User, PgError> {
        if !self.tenant_exists(tenant).await? {
            return Err(PgError::Auth(AuthError::UnknownTenant));
        }
        let username = crate::normalize(username);
        let row = sqlx::query(
            "select username, password_hash from users where tenant_id = $1 and username = $2",
        )
        .bind(tenant.as_str())
        .bind(&username)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => {
                let password_hash: String = row.get("password_hash");
                if crate::verify_password(password, &password_hash) {
                    Ok(User {
                        tenant: tenant.clone(),
                        username: row.get("username"),
                    })
                } else {
                    Err(PgError::Auth(AuthError::InvalidCredentials))
                }
            }
            None => {
                let _ = crate::verify_password(password, crate::dummy_hash());
                Err(PgError::Auth(AuthError::InvalidCredentials))
            }
        }
    }

    /// Authenticate a user and, on success, issue a session token.
    pub async fn sign_in(
        &self,
        tenant: &TenantId,
        identifier: &str,
        password: &str,
    ) -> Result<(User, SessionToken), PgError> {
        let user = self.authenticate_user(tenant, identifier, password).await?;
        let token = crate::random_token("ses");
        let token_hash = crate::sha256(token.as_bytes());
        // expires_at is set from the database clock plus the shared session TTL,
        // so the durable store expires sessions exactly as the in-memory one
        // does (decision record 0043).
        sqlx::query(
            "insert into sessions (token_hash, tenant_id, username, expires_at) \
             values ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(&token_hash[..])
        .bind(user.tenant.as_str())
        .bind(&user.username)
        .bind(crate::SESSION_TTL_SECS as f64)
        .execute(&self.pool)
        .await?;
        Ok((user, SessionToken(token)))
    }

    /// The user a session token authorises — its tenant and username — or
    /// `None` if the token is unknown **or has expired**.
    pub async fn validate_session(
        &self,
        token: &str,
    ) -> Result<Option<(TenantId, String)>, PgError> {
        let hash = crate::sha256(token.as_bytes());
        let row = sqlx::query(
            "select tenant_id, username from sessions \
             where token_hash = $1 and expires_at > now()",
        )
        .bind(&hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| (TenantId(row.get("tenant_id")), row.get("username"))))
    }

    /// Revoke a single session before its TTL (sign-out / stolen token,
    /// decision record 0044). Returns whether a row was removed.
    pub async fn revoke_session(&self, token: &str) -> Result<bool, PgError> {
        let hash = crate::sha256(token.as_bytes());
        let res = sqlx::query("delete from sessions where token_hash = $1")
            .bind(&hash[..])
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Revoke every session for a user (sign-out-everywhere / compromise
    /// response). Returns how many were removed.
    pub async fn revoke_user_sessions(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<u64, PgError> {
        let username = crate::normalize(username);
        let res = sqlx::query("delete from sessions where tenant_id = $1 and username = $2")
            .bind(tenant.as_str())
            .bind(&username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Delete every session whose expiry has passed (the database clock decides).
    /// Memory hygiene — `validate_session` already refuses expired rows. Returns
    /// how many were removed.
    pub async fn sweep_expired_sessions(&self) -> Result<u64, PgError> {
        let res = sqlx::query("delete from sessions where expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// The directory handle for a `(tenant, username)`,
    /// `"<tenant-username>/<username>"`, or `None` if the tenant is unknown. The
    /// username is normalized like every other account lookup, so any spelling
    /// of it gives the one handle.
    pub async fn handle(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<String>, PgError> {
        let tenant_username: Option<String> =
            sqlx::query_scalar("select username from tenants where id = $1")
                .bind(tenant.as_str())
                .fetch_optional(&self.pool)
                .await?;
        Ok(tenant_username.map(|t| format!("{t}/{}", crate::normalize(username))))
    }

    /// Read a user's durable device inventory. Existing accounts without a
    /// stored row are represented by the empty generation-zero inventory.
    pub async fn device_inventory(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<DeviceInventory>, PgError> {
        let username = crate::normalize(username);
        let row = sqlx::query(
            "select t.username as tenant_username, i.state \
             from users u join tenants t on t.id = u.tenant_id \
             left join account_device_inventories i \
               on i.tenant_id = u.tenant_id and i.username = u.username \
             where u.tenant_id = $1 and u.username = $2",
        )
        .bind(tenant.as_str())
        .bind(&username)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let handle = format!("{}/{}", row.get::<String, _>("tenant_username"), username);
        let inventory = match row.get::<Option<Vec<u8>>, _>("state") {
            Some(bytes) => {
                decode_inventory(&bytes).ok_or(PgError::Inventory(InventoryError::Invalid))?
            }
            None => DeviceInventory::default(),
        };
        validate_inventory(&handle, &inventory).map_err(PgError::Inventory)?;
        Ok(Some(inventory))
    }

    /// Atomically replace an account inventory at its exact predecessor
    /// generation after the provisioning layer has checked authorization and
    /// possession of the new identity key.
    pub async fn link_device_binding(
        &self,
        tenant: &TenantId,
        username: &str,
        predecessor_generation: u64,
        idempotency_key: [u8; 32],
        binding: DeviceBinding,
    ) -> Result<DeviceInventory, PgError> {
        let request = encode_link_request(predecessor_generation, &binding);
        self.mutate_inventory(
            tenant,
            username,
            idempotency_key,
            request,
            move |handle, current| link_inventory(handle, current, predecessor_generation, binding),
        )
        .await
    }

    /// Atomically terminally revoke one exact active binding. The caller has
    /// already checked the lifecycle authorization and continuity/recovery
    /// proof; this method supplies durable generation and retry semantics.
    pub async fn revoke_device_binding(
        &self,
        tenant: &TenantId,
        username: &str,
        predecessor_generation: u64,
        idempotency_key: [u8; 32],
        retired: DeviceBinding,
    ) -> Result<DeviceInventory, PgError> {
        let request = encode_revoke_request(predecessor_generation, &retired);
        self.mutate_inventory(
            tenant,
            username,
            idempotency_key,
            request,
            move |handle, current| {
                revoke_inventory(handle, current, predecessor_generation, retired)
            },
        )
        .await
    }

    /// Atomically retire one exact active binding and activate its committed
    /// successor. The caller has already checked the lifecycle proofs.
    pub async fn replace_device_binding(
        &self,
        tenant: &TenantId,
        username: &str,
        predecessor_generation: u64,
        idempotency_key: [u8; 32],
        retired: DeviceBinding,
        replacement: DeviceBinding,
    ) -> Result<DeviceInventory, PgError> {
        let request = encode_replace_request(predecessor_generation, &retired, &replacement);
        self.mutate_inventory(
            tenant,
            username,
            idempotency_key,
            request,
            move |handle, current| {
                replace_inventory(
                    handle,
                    current,
                    predecessor_generation,
                    retired,
                    replacement,
                )
            },
        )
        .await
    }

    /// One inventory mutation in one transaction. The order of its statements
    /// (lock the account, then read, then compare-and-set) is in
    /// [`apply_mutation`]; this only opens the transaction and commits it on
    /// success, so a refusal or an error rolls back when the transaction drops.
    async fn mutate_inventory(
        &self,
        tenant: &TenantId,
        username: &str,
        idempotency_key: [u8; 32],
        request: Vec<u8>,
        transition: impl FnOnce(&str, &DeviceInventory) -> Result<DeviceInventory, InventoryError>,
    ) -> Result<DeviceInventory, PgError> {
        let username = crate::normalize(username);
        let mut tx = self.pool.begin().await?;
        // The order of statements in `apply_mutation` relies on each statement
        // seeing what was committed when it began. Say so rather than depend on
        // the server's default isolation level; this must be the first
        // statement of the transaction.
        sqlx::query("set transaction isolation level read committed")
            .execute(&mut *tx)
            .await?;
        let next = apply_mutation(
            &mut PgInventoryTx(&mut tx),
            tenant,
            &username,
            idempotency_key,
            &request,
            transition,
        )
        .await
        .map_err(|error| match error {
            MutationError::Refused(refusal) => PgError::Inventory(refusal),
            MutationError::Backend(error) => PgError::Database(error),
        })?;
        tx.commit().await?;
        Ok(next)
    }

    async fn tenant_exists(&self, tenant: &TenantId) -> Result<bool, PgError> {
        let id: Option<String> = sqlx::query_scalar("select id from tenants where id = $1")
            .bind(tenant.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(id.is_some())
    }
}

/// The statements of one inventory mutation, over an open Postgres transaction.
///
/// Each method is one SQL statement, so each gets its own snapshot under
/// `READ COMMITTED`. That is what makes [`stored_state`] see everything
/// committed before the lock in [`lock_account`] was granted.
///
/// [`lock_account`]: InventoryTx::lock_account
/// [`stored_state`]: InventoryTx::stored_state
struct PgInventoryTx<'a, 'c>(&'a mut sqlx::Transaction<'c, sqlx::Postgres>);

impl InventoryTx for PgInventoryTx<'_, '_> {
    type Error = sqlx::Error;

    async fn lock_account(
        &mut self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        // `for no key update` serializes mutations of this account (each takes
        // the same lock) without blocking inserts into tables that reference
        // `users` by foreign key, such as a sign-in creating a session; those
        // take only `for key share`, which `for update` would conflict with.
        // The inventory is deliberately not part of this statement: see
        // [`InventoryTx::stored_state`].
        let tenant_username: Option<String> = sqlx::query_scalar(
            "select t.username \
             from users u join tenants t on t.id = u.tenant_id \
             where u.tenant_id = $1 and u.username = $2 for no key update of u",
        )
        .bind(tenant.as_str())
        .bind(username)
        .fetch_optional(&mut **self.0)
        .await?;
        Ok(tenant_username.map(|t| format!("{t}/{username}")))
    }

    async fn prior_mutation(
        &mut self,
        tenant: &TenantId,
        username: &str,
        key: &[u8; 32],
    ) -> Result<Option<PriorMutation>, sqlx::Error> {
        let row = sqlx::query(
            "select request, result from account_inventory_mutations \
             where tenant_id = $1 and username = $2 and idempotency_key = $3",
        )
        .bind(tenant.as_str())
        .bind(username)
        .bind(&key[..])
        .fetch_optional(&mut **self.0)
        .await?;
        Ok(row.map(|row| PriorMutation {
            request: row.get("request"),
            result: row.get("result"),
        }))
    }

    async fn stored_state(
        &mut self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        sqlx::query_scalar(
            "select state from account_device_inventories \
             where tenant_id = $1 and username = $2",
        )
        .bind(tenant.as_str())
        .bind(username)
        .fetch_optional(&mut **self.0)
        .await
    }

    async fn compare_and_set_state(
        &mut self,
        tenant: &TenantId,
        username: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let result = match expected {
            // No row was read, so insert one and match nothing if a row exists
            // by now.
            None => {
                sqlx::query(
                    "insert into account_device_inventories (tenant_id, username, state) \
                     values ($1, $2, $3) \
                     on conflict (tenant_id, username) do nothing",
                )
                .bind(tenant.as_str())
                .bind(username)
                .bind(next)
                .execute(&mut **self.0)
                .await?
            }
            // Replace the row only if it still holds the bytes that were read.
            Some(expected) => {
                sqlx::query(
                    "update account_device_inventories set state = $3 \
                     where tenant_id = $1 and username = $2 and state = $4",
                )
                .bind(tenant.as_str())
                .bind(username)
                .bind(next)
                .bind(expected)
                .execute(&mut **self.0)
                .await?
            }
        };
        Ok(result.rows_affected() == 1)
    }

    async fn record_mutation(
        &mut self,
        tenant: &TenantId,
        username: &str,
        key: &[u8; 32],
        request: &[u8],
        result: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into account_inventory_mutations \
             (tenant_id, username, idempotency_key, request, result) \
             values ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.as_str())
        .bind(username)
        .bind(&key[..])
        .bind(request)
        .bind(result)
        .execute(&mut **self.0)
        .await?;
        Ok(())
    }
}

/// The lost-update race, forced on a real server.
///
/// `tests/pg.rs` runs mutations from many tasks, but each transaction is a
/// fraction of a millisecond, so the tasks need not overlap and the race can
/// go unseen. With the row lock and the compare-and-set both removed those
/// tests still pass. This one makes the overlap certain: two transactions each
/// wait, after reading the stored state, until the other has read it too, so
/// both hold the same generation before either writes.
///
/// With the lock in place the second transaction cannot reach its read until
/// the first commits, so the wait is bounded and expires; the first then
/// commits and the second is refused. Without the lock and without the
/// compare-and-set both writes succeed and one mutation is silently lost.
///
/// Skipped unless `TACENTA_TEST_DATABASE_URL` is set.
#[cfg(test)]
mod interleaving {
    use super::*;
    use crate::inventory::{encode_link_request, link_inventory};
    use crate::inventory_tx::{InventoryTx, MutationError, PriorMutation, apply_mutation};
    use crate::{DeviceInventory, InventoryError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tacenta_core::crypto::groups::inventory::GROUP_EPOCH_V1;

    /// Postgres, except that after the state is read the transaction waits
    /// (bounded) for the other one to have read it as well.
    struct Interposed<'a, 'c> {
        inner: PgInventoryTx<'a, 'c>,
        arrived: Arc<AtomicUsize>,
    }

    impl InventoryTx for Interposed<'_, '_> {
        type Error = sqlx::Error;

        async fn lock_account(
            &mut self,
            tenant: &TenantId,
            username: &str,
        ) -> Result<Option<String>, sqlx::Error> {
            self.inner.lock_account(tenant, username).await
        }

        async fn prior_mutation(
            &mut self,
            tenant: &TenantId,
            username: &str,
            key: &[u8; 32],
        ) -> Result<Option<PriorMutation>, sqlx::Error> {
            self.inner.prior_mutation(tenant, username, key).await
        }

        async fn stored_state(
            &mut self,
            tenant: &TenantId,
            username: &str,
        ) -> Result<Option<Vec<u8>>, sqlx::Error> {
            let state = self.inner.stored_state(tenant, username).await?;
            self.arrived.fetch_add(1, Ordering::SeqCst);
            for _ in 0..200 {
                if self.arrived.load(Ordering::SeqCst) >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(state)
        }

        async fn compare_and_set_state(
            &mut self,
            tenant: &TenantId,
            username: &str,
            expected: Option<&[u8]>,
            next: &[u8],
        ) -> Result<bool, sqlx::Error> {
            self.inner
                .compare_and_set_state(tenant, username, expected, next)
                .await
        }

        async fn record_mutation(
            &mut self,
            tenant: &TenantId,
            username: &str,
            key: &[u8; 32],
            request: &[u8],
            result: &[u8],
        ) -> Result<(), sqlx::Error> {
            self.inner
                .record_mutation(tenant, username, key, request, result)
                .await
        }
    }

    async fn link_at_generation_one(
        pool: PgPool,
        tenant: TenantId,
        arrived: Arc<AtomicUsize>,
        id: u8,
    ) -> Result<DeviceInventory, InventoryError> {
        let binding = DeviceBinding {
            device_id: u32::from(id),
            identity_public_key: crate::inventory_rules_tests::honest_key(id),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        let request = encode_link_request(1, &binding);
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("set transaction isolation level read committed")
            .execute(&mut *tx)
            .await
            .expect("isolation");
        let mut shim = Interposed {
            inner: PgInventoryTx(&mut tx),
            arrived,
        };
        let outcome = apply_mutation(
            &mut shim,
            &tenant,
            "alice",
            [id; 32],
            &request,
            move |handle, current| link_inventory(handle, current, 1, binding),
        )
        .await;
        match outcome {
            Ok(next) => {
                tx.commit().await.expect("commit");
                Ok(next)
            }
            Err(MutationError::Refused(refusal)) => Err(refusal),
            Err(MutationError::Backend(error)) => panic!("backend failure: {error}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_transactions_that_both_read_generation_one_admit_exactly_one() {
        let Ok(url) = std::env::var("TACENTA_TEST_DATABASE_URL") else {
            eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
            return;
        };
        let store = PgAccounts::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        store.truncate().await.expect("clean slate");
        let (tenant, _) = store
            .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
            .await
            .unwrap();
        store
            .sign_up_user(&tenant.id, "alice", "hunter2!!")
            .await
            .unwrap();
        // Generation 1 exists, so both mutations below are guarded updates.
        let first = DeviceBinding {
            device_id: 100,
            identity_public_key: crate::inventory_rules_tests::honest_key(100),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        store
            .link_device_binding(&tenant.id, "alice", 0, [100; 32], first)
            .await
            .unwrap();

        let arrived = Arc::new(AtomicUsize::new(0));
        let a = tokio::spawn(link_at_generation_one(
            store.pool.clone(),
            tenant.id.clone(),
            arrived.clone(),
            1,
        ));
        let b = tokio::spawn(link_at_generation_one(
            store.pool.clone(),
            tenant.id.clone(),
            arrived.clone(),
            2,
        ));
        let results = [a.await.unwrap(), b.await.unwrap()];
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let refused = results
            .iter()
            .filter(|r| matches!(r, Err(InventoryError::PredecessorMismatch)))
            .count();
        assert_eq!(wins, 1, "exactly one may take generation 2: {results:?}");
        assert_eq!(refused, 1, "the other is refused as stale: {results:?}");

        let stored = store
            .device_inventory(&tenant.id, "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.generation, 2);
        assert_eq!(stored.active.len(), 2, "the first binding and the winner");
    }
}
