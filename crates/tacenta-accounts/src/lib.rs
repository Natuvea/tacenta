//! The account and tenant model — Tacenta's control-plane identity layer.
//!
//! A **tenant** is a customer organisation, holding an API key that isolates
//! its users; a **user** is an account within a tenant. A tenant signs up
//! with a unique username, email, and password; a user with a unique username
//! and password. Passwords are hashed with argon2id (never stored or compared
//! in the clear); uniqueness is enforced on the username and email, never on
//! the password. A user's `username` is their messaging handle. Uniqueness is
//! **global** for tenants and **per-tenant** for users, so the same username
//! can belong to a user in two different tenants — real tenant isolation.
//!
//! 2FA and passkeys are deliberately out of scope for now; the credential
//! model is a password today and grows additively later. The verified
//! protocol core (`tacenta-wire` / `state` / `directory` / `relay`) knows
//! nothing about tenants — this crate is where tenancy lives, and it maps a
//! `(tenant, username)` to the handle the directory binds. The store is
//! in-memory today; it is the natural first consumer of the durable store
//! (decision record 0030).

use std::collections::HashMap;
use std::sync::OnceLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::{RngCore as _, TryRngCore as _};
use sha2::{Digest, Sha256};

mod id;
mod persist;
#[cfg(feature = "postgres")]
pub mod pg;
mod protocol;
mod ratelimit;
mod store;
pub use protocol::{
    AccountRequest, AccountResponse, SignupReason, decode_account_request, decode_account_response,
    encode_account_request, encode_account_response,
};
pub use store::{AccountStore, StoreError};

/// An opaque tenant identifier.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TenantId(String);

impl TenantId {
    /// The identifier as a string, for logging or as a map key elsewhere.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstruct an identifier from its string form — the inverse of
    /// [`as_str`](TenantId::as_str), for a caller that round-trips ids through
    /// storage. This asserts nothing about whether the tenant exists.
    pub fn from_string(id: impl Into<String>) -> TenantId {
        TenantId(id.into())
    }
}

/// An API key, returned once when a tenant is created. The store keeps only a
/// hash of it, so this plaintext is the only copy — a caller that wants to use
/// it later must save it now.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ApiKey(String);

/// The prefix and nothing else: a derived `Debug` printed the whole key, and
/// a key that reaches a log line is a key that leaked.
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiKey({}…)", &self.0[..self.0.len().min(4)])
    }
}

impl ApiKey {
    /// The key as a string, to present on a request.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The non-secret identifying prefix — the first [`KEY_PREFIX_LEN`]
    /// characters (`tct_` plus eight hex). Safe to display and store so a tenant
    /// can recognise a key in a list and revoke it by prefix; the rest stays
    /// secret (a 12-char prefix reveals 32 of the key's 256 bits).
    pub fn prefix(&self) -> String {
        self.0.chars().take(KEY_PREFIX_LEN).collect()
    }
}

/// How many leading characters of an API key form its non-secret prefix.
const KEY_PREFIX_LEN: usize = 12;

/// A tenant's view of one of its API keys: the non-secret prefix, an optional
/// label, and when it was created (unix seconds). Never the key itself — the
/// store keeps only a hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyInfo {
    pub prefix: String,
    pub label: Option<String>,
    pub created_at: u64,
}

/// A session token, issued on a successful sign-in. The holder presents it to
/// authorise an account action (such as provisioning a device) without
/// re-sending the password. The store keeps only its hash, so this plaintext
/// is the only copy. A session expires a fixed time after sign-in
/// (`SESSION_TTL_SECS`); after that the token authorises nothing and the holder
/// signs in again for a fresh one.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionToken(String);

/// The prefix only, for the same reason as `ApiKey`'s.
impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken({}…)", &self.0[..self.0.len().min(4)])
    }
}

impl SessionToken {
    /// The token as a string, to present on a request.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A tenant: a customer organisation with an API key isolating its users.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    pub username: String,
    pub email: String,
}

/// A user within a tenant. `username` is the user's messaging handle, unique
/// within the tenant, and the only identifier a user signs up with — users have
/// no email (only tenants do). 2FA and passkeys grow the credential model
/// additively later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub tenant: TenantId,
    pub username: String,
}

/// Why a signup was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignupError {
    /// The username is already taken in this scope.
    UsernameTaken,
    /// The email is already registered in this scope.
    EmailTaken,
    /// The username is empty, too long, or has disallowed characters.
    InvalidUsername,
    /// The email is not a plausible address.
    InvalidEmail,
    /// The password is shorter than the minimum (or implausibly long).
    WeakPassword,
    /// A user signup named a tenant that does not exist.
    UnknownTenant,
}

/// Why an authentication attempt failed. Deliberately coarse: it does not
/// separate "no such account" from "wrong password", so it cannot serve to
/// probe which accounts exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The identifier and password did not match a known account.
    InvalidCredentials,
    /// The named tenant does not exist.
    UnknownTenant,
    /// Too many recent failed attempts for this identifier; the credential
    /// check was refused without running. Throttles online password guessing.
    /// Keyed so it is not an account-existence oracle (see `ratelimit`).
    RateLimited,
}

struct TenantRecord {
    id: TenantId,
    username: String,
    email: String,
    password_hash: String,
}

struct UserRecord {
    tenant: TenantId,
    username: String,
    password_hash: String,
}

struct ApiKeyRecord {
    tenant: TenantId,
    prefix: String,
    label: Option<String>,
    created_at: u64,
}

/// The account store: tenants and their users, with the indexes that enforce
/// uniqueness and answer lookups.
#[derive(Default)]
pub struct Accounts {
    tenants: HashMap<TenantId, TenantRecord>,
    tenant_by_username: HashMap<String, TenantId>,
    tenant_by_email: HashMap<String, TenantId>,
    // sha256(api key) -> the key's tenant and non-secret metadata. A tenant may
    // hold several (rotation): the map is keyed by key, not by tenant.
    api_keys: HashMap<[u8; 32], ApiKeyRecord>,
    users: HashMap<(TenantId, String), UserRecord>,
    // sha256(session token) -> (tenant, username, expires_at unix seconds).
    sessions: HashMap<[u8; 32], (TenantId, String, u64)>,
    // Failed-sign-in throttle, keyed by (tenant, identifier).
    limiter: ratelimit::RateLimiter,
}

impl Accounts {
    /// An empty store.
    pub fn new() -> Accounts {
        Accounts::default()
    }

    /// Sign up a new tenant. Username and email are unique across all tenants.
    /// Returns the tenant and its API key; the key is shown only here.
    pub fn sign_up_tenant(
        &mut self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(Tenant, ApiKey), SignupError> {
        let username = normalize_username(username)?;
        let email = normalize_email(email)?;
        validate_password(password)?;
        if self.tenant_by_username.contains_key(&username) {
            return Err(SignupError::UsernameTaken);
        }
        if self.tenant_by_email.contains_key(&email) {
            return Err(SignupError::EmailTaken);
        }

        let id = TenantId(crate::id::prefixed("ten"));
        let (api_key, api_key_hash) = generate_api_key();
        self.tenants.insert(
            id.clone(),
            TenantRecord {
                id: id.clone(),
                username: username.clone(),
                email: email.clone(),
                password_hash: hash_password(password),
            },
        );
        self.tenant_by_username.insert(username.clone(), id.clone());
        self.tenant_by_email.insert(email.clone(), id.clone());
        self.api_keys.insert(
            api_key_hash,
            ApiKeyRecord {
                tenant: id.clone(),
                prefix: api_key.prefix(),
                label: None,
                created_at: current_unix(),
            },
        );
        Ok((
            Tenant {
                id,
                username,
                email,
            },
            api_key,
        ))
    }

    /// Authenticate a tenant by its username or email plus password.
    pub fn authenticate_tenant(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<TenantId, AuthError> {
        let key = normalize(identifier);
        let found = self
            .tenant_by_username
            .get(&key)
            .or_else(|| self.tenant_by_email.get(&key));
        match found {
            Some(id) if verify_password(password, &self.tenants[id].password_hash) => {
                Ok(id.clone())
            }
            Some(_) => Err(AuthError::InvalidCredentials),
            // Verify against a dummy hash so a missing account takes the same
            // time as a wrong password — no user-enumeration timing oracle.
            None => {
                let _ = verify_password(password, dummy_hash());
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    /// The tenant an API key belongs to, if any. Looks up by the key's hash;
    /// the plaintext key is never stored.
    pub fn tenant_by_api_key(&self, api_key: &str) -> Option<TenantId> {
        self.api_keys
            .get(&sha256(api_key.as_bytes()))
            .map(|record| record.tenant.clone())
    }

    /// Mint an additional API key for a tenant, returned once (the store keeps
    /// only its hash). A tenant already holds one from signup; this is how it
    /// rotates — add a new key, deploy it, revoke the old (decision record 0048).
    pub fn create_api_key(
        &mut self,
        tenant: &TenantId,
        label: Option<String>,
    ) -> Result<ApiKey, AuthError> {
        if !self.tenants.contains_key(tenant) {
            return Err(AuthError::UnknownTenant);
        }
        let (api_key, api_key_hash) = generate_api_key();
        self.api_keys.insert(
            api_key_hash,
            ApiKeyRecord {
                tenant: tenant.clone(),
                prefix: api_key.prefix(),
                label,
                created_at: current_unix(),
            },
        );
        Ok(api_key)
    }

    /// The API keys a tenant holds — prefix, label, and creation time, never the
    /// secret — newest first.
    pub fn list_api_keys(&self, tenant: &TenantId) -> Vec<ApiKeyInfo> {
        let mut keys: Vec<ApiKeyInfo> = self
            .api_keys
            .values()
            .filter(|record| &record.tenant == tenant)
            .map(|record| ApiKeyInfo {
                prefix: record.prefix.clone(),
                label: record.label.clone(),
                created_at: record.created_at,
            })
            .collect();
        keys.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(a.prefix.cmp(&b.prefix))
        });
        keys
    }

    /// Revoke a tenant's API key by its prefix, so it stops resolving at once —
    /// the leaked-key response. Returns whether one was removed. A tenant that
    /// revokes its last key can always mint another with its password, so there
    /// is no lock-out to guard against.
    pub fn revoke_api_key(&mut self, tenant: &TenantId, prefix: &str) -> bool {
        let before = self.api_keys.len();
        self.api_keys
            .retain(|_, record| !(&record.tenant == tenant && record.prefix == prefix));
        before != self.api_keys.len()
    }

    /// Fetch a tenant by id.
    pub fn tenant(&self, id: &TenantId) -> Option<Tenant> {
        self.tenants.get(id).map(|t| Tenant {
            id: t.id.clone(),
            username: t.username.clone(),
            email: t.email.clone(),
        })
    }

    /// Sign up a new user within a tenant. The username is unique within that
    /// tenant only and is the user's messaging handle. Users have no email —
    /// only tenants do.
    pub fn sign_up_user(
        &mut self,
        tenant: &TenantId,
        username: &str,
        password: &str,
    ) -> Result<User, SignupError> {
        if !self.tenants.contains_key(tenant) {
            return Err(SignupError::UnknownTenant);
        }
        let username = normalize_username(username)?;
        validate_password(password)?;
        if self.users.contains_key(&(tenant.clone(), username.clone())) {
            return Err(SignupError::UsernameTaken);
        }

        self.users.insert(
            (tenant.clone(), username.clone()),
            UserRecord {
                tenant: tenant.clone(),
                username: username.clone(),
                password_hash: hash_password(password),
            },
        );
        Ok(User {
            tenant: tenant.clone(),
            username,
        })
    }

    /// Authenticate a user within a tenant by username plus password.
    pub fn authenticate_user(
        &self,
        tenant: &TenantId,
        username: &str,
        password: &str,
    ) -> Result<User, AuthError> {
        if !self.tenants.contains_key(tenant) {
            return Err(AuthError::UnknownTenant);
        }
        let username = normalize(username);
        match self.users.get(&(tenant.clone(), username)) {
            Some(u) if verify_password(password, &u.password_hash) => Ok(User {
                tenant: u.tenant.clone(),
                username: u.username.clone(),
            }),
            Some(_) => Err(AuthError::InvalidCredentials),
            None => {
                let _ = verify_password(password, dummy_hash());
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    /// Authenticate a user (as [`authenticate_user`](Accounts::authenticate_user))
    /// and, on success, issue a session token bound to that user. The token is
    /// returned once; the store keeps only its hash.
    /// Rate-limited against online password guessing: too many recent failed
    /// attempts for this identifier are refused with
    /// [`AuthError::RateLimited`](AuthError::RateLimited) before the credential
    /// check runs (see [`ratelimit`]).
    pub fn sign_in(
        &mut self,
        tenant: &TenantId,
        identifier: &str,
        password: &str,
    ) -> Result<(User, SessionToken), AuthError> {
        self.sign_in_at(current_unix(), tenant, identifier, password)
    }

    /// [`sign_in`](Accounts::sign_in) with an explicit clock (`now`, unix
    /// seconds) instead of the system clock, so the rate-limit policy is
    /// deterministically testable. `sign_in` is exactly this with the real
    /// clock; a caller with its own time source (e.g. a transport that also
    /// rate-limits by IP) can supply one here.
    pub fn sign_in_at(
        &mut self,
        now: u64,
        tenant: &TenantId,
        identifier: &str,
        password: &str,
    ) -> Result<(User, SessionToken), AuthError> {
        let key = ratelimit_key(tenant, identifier);
        if self.limiter.is_blocked(&key, now) {
            return Err(AuthError::RateLimited);
        }
        // **A flood is refused before argon2 runs at all**, which the
        // per-identifier ceiling above cannot do: a caller cycling identifiers
        // never reaches it on any single key, while every attempt still costs
        // 19 MiB because unknown accounts run the dummy verify. The trade this
        // makes -- enumeration resistance for
        // availability, and only while the flood lasts -- is argued at
        // `TENANT_FLOOD_CEILING`.
        if self.limiter.tenant_is_flooded(&tenant_prefix(tenant), now) {
            self.limiter.record_failure(&key, now);
            return Err(AuthError::RateLimited);
        }
        match self.authenticate_user(tenant, identifier, password) {
            Ok(user) => {
                self.limiter.record_success(&key);
                let token = SessionToken(random_token("ses"));
                self.sessions.insert(
                    sha256(token.as_str().as_bytes()),
                    (
                        user.tenant.clone(),
                        user.username.clone(),
                        now.saturating_add(SESSION_TTL_SECS),
                    ),
                );
                Ok((user, token))
            }
            Err(e) => {
                // Any failure — wrong password, unknown account, unknown
                // tenant — counts toward the throttle, so guessing gains no
                // signal from which error it is.
                self.limiter.record_failure(&key, now);
                Err(e)
            }
        }
    }

    /// The user a session token authorises — its tenant and username — or
    /// `None` if the token is unknown **or has expired**. Looks up by the
    /// token's hash; the plaintext token is never stored.
    pub fn validate_session(&self, token: &str) -> Option<(TenantId, String)> {
        self.validate_session_at(current_unix(), token)
    }

    /// [`validate_session`](Accounts::validate_session) with an explicit clock
    /// (`now`, unix seconds), so session expiry is deterministically testable.
    /// A session is valid only until its `expires_at`; an expired token
    /// authorises nothing, exactly as an unknown one does. Expired entries are
    /// left in place (this is a read); they are overwritten on the next sign-in
    /// and a periodic sweep is future work.
    pub fn validate_session_at(&self, now: u64, token: &str) -> Option<(TenantId, String)> {
        self.sessions
            .get(&sha256(token.as_bytes()))
            .filter(|(_, _, expires_at)| now < *expires_at)
            .map(|(tenant, username, _)| (tenant.clone(), username.clone()))
    }

    /// Revoke a single session, so its token stops authorising before its TTL —
    /// the sign-out / stolen-token path. Returns whether a session was removed
    /// (`false` if the token was already unknown, expired-and-swept, or revoked).
    pub fn revoke_session(&mut self, token: &str) -> bool {
        self.sessions.remove(&sha256(token.as_bytes())).is_some()
    }

    /// Revoke **every** session for a user — "sign out everywhere", and the
    /// response to a suspected compromise. Returns how many were removed. A new
    /// sign-in afterwards issues a fresh token, unaffected.
    pub fn revoke_user_sessions(&mut self, tenant: &TenantId, username: &str) -> usize {
        let username = normalize(username);
        let before = self.sessions.len();
        self.sessions
            .retain(|_, (t, u, _)| !(t == tenant && *u == username));
        before - self.sessions.len()
    }

    /// Drop every session that has already expired, reclaiming the space they
    /// hold. `validate_session` never returns an expired session regardless, so
    /// this is memory hygiene, not a correctness fix — a periodic caller (the
    /// server's snapshot tick) runs it. Returns how many were removed.
    pub fn sweep_expired_sessions(&mut self) -> usize {
        self.sweep_expired_sessions_at(current_unix())
    }

    /// [`sweep_expired_sessions`](Accounts::sweep_expired_sessions) with an
    /// explicit clock, for deterministic tests.
    pub fn sweep_expired_sessions_at(&mut self, now: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, (_, _, expires_at)| now < *expires_at);
        before - self.sessions.len()
    }

    /// The directory handle for a `(tenant, username)` — the string peers use
    /// to address the user, `"<tenant-username>/<username>"` (e.g.
    /// `acme/alice`). `None` if the tenant is unknown. This is where the
    /// account layer maps its per-tenant identity onto the tenant-agnostic
    /// directory (decision record 0033).
    pub fn handle(&self, tenant: &TenantId, username: &str) -> Option<String> {
        let tenant_username = &self.tenants.get(tenant)?.username;
        Some(format!("{tenant_username}/{username}"))
    }
}

/// Trim and lowercase, the normal form for a case-insensitive identifier.
fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

/// The rate-limit key for a sign-in: the tenant plus the normalized identifier,
/// joined by a NUL that cannot appear in either part. Keying by identifier (not
/// by resolved user) means the throttle applies whether or not the account
/// exists, so it reveals nothing about existence, and one account's failures
/// cannot lock out another.
fn ratelimit_key(tenant: &TenantId, identifier: &str) -> String {
    format!("{}\u{0}{}", tenant.as_str(), normalize(identifier))
}

/// The prefix every key for one tenant shares, so a coarse count can be taken
/// without a second index. The NUL separator cannot occur in a tenant id, so a
/// prefix match cannot reach into a neighbouring tenant's keys.
fn tenant_prefix(tenant: &TenantId) -> String {
    format!("{}\u{0}", tenant.as_str())
}

/// How long a session token stays valid after sign-in, in seconds (24 hours).
/// A leaked token is otherwise valid forever; this bounds the window. Refreshing
/// or extending sessions is future work — a new sign-in issues a fresh token.
const SESSION_TTL_SECS: u64 = 24 * 60 * 60;

/// The current unix time in seconds, for the sign-in rate limiter and session
/// expiry. Falls back to 0 only if the system clock is before the epoch, which
/// cannot happen in practice; callers degrade safely (treat it as one instant).
fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_username(s: &str) -> Result<String, SignupError> {
    let u = normalize(s);
    let ok = (3..=32).contains(&u.chars().count())
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(u)
    } else {
        Err(SignupError::InvalidUsername)
    }
}

fn normalize_email(s: &str) -> Result<String, SignupError> {
    let e = normalize(s);
    let plausible = e.len() <= 254
        && e.matches('@').count() == 1
        && e.split('@').next().is_some_and(|local| !local.is_empty())
        && e.split('@').nth(1).is_some_and(|domain| {
            domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        });
    if plausible {
        Ok(e)
    } else {
        Err(SignupError::InvalidEmail)
    }
}

fn validate_password(password: &str) -> Result<(), SignupError> {
    // A minimum, and an upper bound so an enormous input cannot turn argon2
    // into a denial-of-service lever.
    if (8..=1024).contains(&password.len()) {
        Ok(())
    } else {
        Err(SignupError::WeakPassword)
    }
}

/// The argon2id work factor, pinned here rather than inherited.
///
/// **Pinned, not taken from `Argon2::default()`.** A default is a security
/// parameter living in a dependency's constant, where a routine version bump
/// moves it with no diff in this repository and no test noticing -- in either
/// direction, since a crate is as free to lower a default as to raise it.
///
/// These are argon2 0.5.3's defaults, so pinning them costs nothing today.
/// That is the point: the value is a decision with a name, and changing it is
/// a visible act.
///
/// Existing hashes are unaffected. A PHC string carries the parameters it was
/// made with, so `verify_password` keeps verifying older hashes at their own
/// cost, whatever this becomes later.
///
/// **That backward compatibility has a cost worth knowing before it is
/// spent.** The dummy hash that equalises the timing of a failed sign-in is
/// built with the parameters here. If these ever rise, a stored hash made under
/// the old cost verifies faster than the dummy, and the difference is
/// measurable -- so raising the cost reopens, for existing accounts, exactly
/// the enumeration channel the dummy exists to close. Re-hashing on successful
/// sign-in is the usual answer, and it is not implemented; do not raise these
/// without it.
const ARGON2_M_COST: u32 = 19 * 1024; // KiB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

fn argon2() -> Argon2<'static> {
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("the pinned argon2 parameters are in range");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn hash_password(password: &str) -> String {
    // Generate the 16-byte salt with the workspace RNG and encode it, rather
    // than depend on the (feature-gated, absent) OsRng in password_hash's
    // pinned rand_core.
    let salt = SaltString::encode_b64(&random_bytes::<16>()).expect("salt encoding");
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing")
        .to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            // The parameters come from the PHC string, not from this instance,
            // which is what lets a hash made under an older cost keep verifying.
            // Built from the pinned configuration anyway, so a reader does not
            // have to work out whether it mattered.
            argon2()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A valid argon2id hash of a fixed placeholder, computed once, giving a
/// missing account the same verification cost as a real one.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("dummy-for-timing-equalization"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut buf);
    buf
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn random_token(prefix: &str) -> String {
    format!("{prefix}_{}", hex(&random_bytes::<16>()))
}

fn generate_api_key() -> (ApiKey, [u8; 32]) {
    let key = format!("tct_{}", hex(&random_bytes::<32>()));
    let hash = sha256(key.as_bytes());
    (ApiKey(key), hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(accounts: &mut Accounts) -> (TenantId, ApiKey) {
        let (t, key) = accounts
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        (t.id, key)
    }

    #[test]
    fn a_tenant_signs_up_and_its_api_key_resolves() {
        let mut a = Accounts::new();
        let (t, key) = a
            .sign_up_tenant("Acme", "Admin@Acme.example", "correct horse")
            .unwrap();
        assert_eq!(t.username, "acme", "username is normalized");
        assert_eq!(t.email, "admin@acme.example");
        assert!(key.as_str().starts_with("tct_"));
        assert_eq!(a.tenant_by_api_key(key.as_str()), Some(t.id));
        assert_eq!(a.tenant_by_api_key("tct_nope"), None);
    }

    #[test]
    fn tenant_username_and_email_are_unique() {
        let mut a = Accounts::new();
        a.sign_up_tenant("acme", "a@acme.example", "correct horse")
            .unwrap();
        assert_eq!(
            a.sign_up_tenant("ACME", "other@x.example", "correct horse"),
            Err(SignupError::UsernameTaken),
        );
        assert_eq!(
            a.sign_up_tenant("other", "A@acme.example", "correct horse"),
            Err(SignupError::EmailTaken),
        );
    }

    #[test]
    fn tenant_authenticates_by_username_or_email() {
        let mut a = Accounts::new();
        let (id, _) = tenant(&mut a);
        assert_eq!(
            a.authenticate_tenant("acme", "correct horse"),
            Ok(id.clone())
        );
        assert_eq!(
            a.authenticate_tenant("admin@acme.example", "correct horse"),
            Ok(id),
        );
        assert_eq!(
            a.authenticate_tenant("acme", "wrong"),
            Err(AuthError::InvalidCredentials),
        );
        assert_eq!(
            a.authenticate_tenant("ghost", "correct horse"),
            Err(AuthError::InvalidCredentials),
        );
    }

    #[test]
    fn users_are_unique_within_a_tenant_but_isolated_across_tenants() {
        let mut a = Accounts::new();
        let (t1, _) = a
            .sign_up_tenant("orgone", "a@t1.example", "correct horse")
            .unwrap();
        let (t2, _) = a
            .sign_up_tenant("orgtwo", "a@t2.example", "correct horse")
            .unwrap();

        a.sign_up_user(&t1.id, "alice", "hunter2!!").unwrap();
        // The same username again in t1 (case-insensitive): rejected.
        assert_eq!(
            a.sign_up_user(&t1.id, "Alice", "hunter2!!"),
            Err(SignupError::UsernameTaken),
        );
        // The very same username in t2: allowed (isolation).
        assert!(a.sign_up_user(&t2.id, "alice", "hunter2!!").is_ok());
    }

    #[test]
    fn a_user_authenticates_within_its_tenant() {
        let mut a = Accounts::new();
        let (id, _) = tenant(&mut a);
        a.sign_up_user(&id, "alice", "hunter2!!").unwrap();

        assert!(a.authenticate_user(&id, "alice", "hunter2!!").is_ok());
        assert_eq!(
            a.authenticate_user(&id, "alice", "nope"),
            Err(AuthError::InvalidCredentials),
        );
        assert_eq!(
            a.authenticate_user(&id, "nobody", "hunter2!!"),
            Err(AuthError::InvalidCredentials),
        );
    }

    #[test]
    fn a_user_needs_a_real_tenant() {
        let mut a = Accounts::new();
        let ghost = TenantId("ten_ghost".into());
        assert_eq!(
            a.sign_up_user(&ghost, "alice", "hunter2!!"),
            Err(SignupError::UnknownTenant),
        );
        assert_eq!(
            a.authenticate_user(&ghost, "alice", "hunter2!!"),
            Err(AuthError::UnknownTenant),
        );
    }

    #[test]
    fn signup_input_is_validated() {
        let mut a = Accounts::new();
        assert_eq!(
            a.sign_up_tenant("ab", "a@x.example", "correct horse"),
            Err(SignupError::InvalidUsername),
        );
        assert_eq!(
            a.sign_up_tenant("acme", "not-an-email", "correct horse"),
            Err(SignupError::InvalidEmail),
        );
        assert_eq!(
            a.sign_up_tenant("acme", "a@x.example", "short"),
            Err(SignupError::WeakPassword),
        );
    }

    #[test]
    fn sign_in_issues_a_session_that_validates() {
        let mut a = Accounts::new();
        let (id, _) = tenant(&mut a);
        a.sign_up_user(&id, "alice", "hunter2!!").unwrap();

        let (user, token) = a.sign_in(&id, "alice", "hunter2!!").unwrap();
        assert_eq!(user.username, "alice");
        assert!(token.as_str().starts_with("ses_"));
        // The token resolves to the user it was issued for.
        assert_eq!(
            a.validate_session(token.as_str()),
            Some((id.clone(), "alice".to_string())),
        );
        // An unknown token resolves to nothing.
        assert_eq!(a.validate_session("ses_nope"), None);
        // A failed sign-in issues no session.
        assert!(a.sign_in(&id, "alice", "wrong").is_err());
        // The directory handle namespaces the user under its tenant.
        assert_eq!(a.handle(&id, "alice").as_deref(), Some("acme/alice"));
    }

    #[test]
    fn a_tenant_can_hold_and_list_several_keys() {
        let mut a = Accounts::new();
        let (id, first) = tenant(&mut a);
        let second = a.create_api_key(&id, Some("ci".to_string())).unwrap();

        // Both keys resolve to the same tenant.
        assert_eq!(a.tenant_by_api_key(first.as_str()), Some(id.clone()));
        assert_eq!(a.tenant_by_api_key(second.as_str()), Some(id.clone()));

        // The list shows both, by prefix, never the secret; the labelled one is
        // labelled.
        let listed = a.list_api_keys(&id);
        assert_eq!(listed.len(), 2);
        let prefixes: Vec<&str> = listed.iter().map(|k| k.prefix.as_str()).collect();
        assert!(prefixes.contains(&first.prefix().as_str()));
        assert!(prefixes.contains(&second.prefix().as_str()));
        assert!(listed.iter().any(|k| k.label.as_deref() == Some("ci")));
        // The prefix identifies but does not reveal the key.
        assert!(first.as_str().starts_with(&first.prefix()));
        assert_ne!(first.as_str(), first.prefix());
    }

    #[test]
    fn revoking_a_key_by_prefix_stops_it_resolving() {
        let mut a = Accounts::new();
        let (id, first) = tenant(&mut a);
        let second = a.create_api_key(&id, None).unwrap();

        // Revoke the first by its prefix.
        assert!(a.revoke_api_key(&id, &first.prefix()));
        assert_eq!(
            a.tenant_by_api_key(first.as_str()),
            None,
            "revoked key is dead"
        );
        // The other key is untouched.
        assert_eq!(a.tenant_by_api_key(second.as_str()), Some(id.clone()));
        assert_eq!(a.list_api_keys(&id).len(), 1);

        // Revoking an unknown prefix removes nothing.
        assert!(!a.revoke_api_key(&id, "tct_notthere"));
        // A tenant can revoke its last key and mint a fresh one.
        assert!(a.revoke_api_key(&id, &second.prefix()));
        assert!(a.list_api_keys(&id).is_empty());
        let third = a.create_api_key(&id, None).unwrap();
        assert_eq!(a.tenant_by_api_key(third.as_str()), Some(id));
    }

    #[test]
    fn one_tenants_key_is_not_another_tenants() {
        let mut a = Accounts::new();
        let (t1, _) = a
            .sign_up_tenant("orgone", "a@t1.example", "correct horse")
            .unwrap();
        let (t2, _) = a
            .sign_up_tenant("orgtwo", "a@t2.example", "correct horse")
            .unwrap();
        let k1 = a.create_api_key(&t1.id, None).unwrap();

        // t2 cannot revoke t1's key by prefix, and does not see it listed.
        assert!(!a.revoke_api_key(&t2.id, &k1.prefix()));
        assert!(
            a.list_api_keys(&t2.id)
                .iter()
                .all(|k| k.prefix != k1.prefix())
        );
        assert_eq!(a.tenant_by_api_key(k1.as_str()), Some(t1.id));
    }
}

#[cfg(test)]
mod work_factor_tests {
    use super::*;

    /// **The work factor is pinned, and this is what pins it.**
    ///
    /// A cost taken from `Argon2::default()` would move with a routine
    /// dependency bump, with no diff here. The constants say what it is; this
    /// says a change to them is deliberate rather than inherited.
    #[test]
    fn the_argon2_cost_is_what_the_documentation_says() {
        assert_eq!(ARGON2_M_COST, 19 * 1024, "19 MiB");
        assert_eq!(ARGON2_T_COST, 2);
        assert_eq!(ARGON2_P_COST, 1);
    }

    /// A hash carries its own parameters, which is what makes an old hash keep
    /// working after the cost changes. Checked rather than assumed, because the
    /// whole backward-compatibility argument rests on it.
    #[test]
    fn a_hash_records_the_cost_it_was_made_with() {
        let hashed = hash_password("a password long enough");
        assert!(
            hashed.contains(&format!("m={ARGON2_M_COST}"))
                && hashed.contains(&format!("t={ARGON2_T_COST}")),
            "the PHC string must carry its parameters: {hashed}"
        );
        assert!(verify_password("a password long enough", &hashed));
        assert!(!verify_password("the wrong password", &hashed));
    }
}
