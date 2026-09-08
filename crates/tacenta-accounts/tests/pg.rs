//! The Postgres-backed store, exercised against a real database. Runs only
//! when `TACENTA_TEST_DATABASE_URL` is set (and the `postgres` feature is on);
//! it skips cleanly otherwise, so the default `cargo test` needs no database.
//!
//!   TACENTA_TEST_DATABASE_URL=postgres://user:pw@host/db \
//!     cargo test -p tacenta-accounts --features postgres --test pg
#![cfg(feature = "postgres")]
// The serialization guard (`db_serial`) is intentionally held across awaits:
// its whole job is to keep these shared-database tests from overlapping, and
// each runs on its own current-thread runtime, so there is no re-entrancy or
// deadlock for the lint to protect against.
#![allow(clippy::await_holding_lock)]

use tacenta_accounts::pg::{PgAccounts, PgError};
use tacenta_accounts::{AuthError, SignupError};

/// Serialize the Postgres tests: they share one database and each starts by
/// truncating it, so they must not run concurrently. Held for the whole test.
fn db_serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Connect, migrate, and start from a clean slate — or `None` to skip.
async fn store() -> Option<PgAccounts> {
    let url = std::env::var("TACENTA_TEST_DATABASE_URL").ok()?;
    let store = PgAccounts::connect(&url)
        .await
        .expect("connect to test database");
    store.migrate().await.expect("run migrations");
    store.truncate().await.expect("clean slate");
    Some(store)
}

#[tokio::test]
async fn the_account_flow_works_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };

    // Tenant signup returns a tenant and an API key that resolves it.
    let (tenant, api_key) = store
        .sign_up_tenant("Acme", "Admin@Acme.example", "correct horse")
        .await
        .unwrap();
    assert_eq!(tenant.username, "acme", "normalized");
    assert!(tenant.id.as_str().starts_with("ten_"));
    assert_eq!(
        store.tenant_by_api_key(api_key.as_str()).await.unwrap(),
        Some(tenant.id.clone()),
    );

    // Tenant username/email uniqueness is a database constraint.
    assert!(matches!(
        store
            .sign_up_tenant("acme", "x@y.example", "correct horse")
            .await,
        Err(PgError::Signup(SignupError::UsernameTaken)),
    ));
    assert!(matches!(
        store
            .sign_up_tenant("other", "admin@acme.example", "correct horse")
            .await,
        Err(PgError::Signup(SignupError::EmailTaken)),
    ));

    // Tenant sign-in.
    assert_eq!(
        store
            .authenticate_tenant("acme", "correct horse")
            .await
            .unwrap(),
        tenant.id,
    );
    assert!(matches!(
        store.authenticate_tenant("acme", "wrong").await,
        Err(PgError::Auth(AuthError::InvalidCredentials)),
    ));

    // A user under the tenant; per-tenant username uniqueness is a constraint.
    store
        .sign_up_user(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    assert!(matches!(
        store.sign_up_user(&tenant.id, "Alice", "hunter2!!").await,
        Err(PgError::Signup(SignupError::UsernameTaken)),
    ));

    // Sign in issues a session that validates; the handle resolves.
    let (_, token) = store
        .sign_in(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    assert_eq!(
        store.validate_session(token.as_str()).await.unwrap(),
        Some((tenant.id.clone(), "alice".to_string())),
    );
    assert_eq!(store.validate_session("ses_nope").await.unwrap(), None);
    assert!(matches!(
        store.sign_in(&tenant.id, "alice", "wrong").await,
        Err(PgError::Auth(AuthError::InvalidCredentials)),
    ));
    assert_eq!(
        store.handle(&tenant.id, "alice").await.unwrap().as_deref(),
        Some("acme/alice"),
    );

    // Tenant isolation: the same username lives in another tenant.
    let (t2, _) = store
        .sign_up_tenant("beta", "admin@beta.example", "correct horse")
        .await
        .unwrap();
    assert!(
        store
            .sign_up_user(&t2.id, "alice", "hunter2!!")
            .await
            .is_ok()
    );

    // `tenant` fetch, and `authenticate_user` directly (by username).
    assert_eq!(store.tenant(&tenant.id).await.unwrap().unwrap(), tenant);
    assert!(
        store
            .authenticate_user(&tenant.id, "alice", "hunter2!!")
            .await
            .is_ok()
    );

    // Input validation on tenant signup (beyond the username case above).
    assert!(matches!(
        store
            .sign_up_tenant("gamma", "not-an-email", "correct horse")
            .await,
        Err(PgError::Signup(SignupError::InvalidEmail)),
    ));
    assert!(matches!(
        store
            .sign_up_tenant("gamma", "gamma@x.example", "short")
            .await,
        Err(PgError::Signup(SignupError::WeakPassword)),
    ));
    assert!(matches!(
        store.sign_up_user(&tenant.id, "ab", "hunter2!!").await,
        Err(PgError::Signup(SignupError::InvalidUsername)),
    ));

    // The "not found" and "unknown tenant" branches.
    let ghost = tacenta_accounts::TenantId::from_string("ten_does_not_exist");
    assert_eq!(store.tenant(&ghost).await.unwrap(), None);
    assert_eq!(store.tenant_by_api_key("tct_nope").await.unwrap(), None);
    assert_eq!(store.handle(&ghost, "alice").await.unwrap(), None);
    assert!(matches!(
        store.authenticate_tenant("nobody", "correct horse").await,
        Err(PgError::Auth(AuthError::InvalidCredentials)),
    ));
    assert!(matches!(
        store.sign_up_user(&ghost, "carol", "hunter2!!").await,
        Err(PgError::Signup(SignupError::UnknownTenant)),
    ));
    assert!(matches!(
        store.authenticate_user(&ghost, "carol", "hunter2!!").await,
        Err(PgError::Auth(AuthError::UnknownTenant)),
    ));
}

#[tokio::test]
async fn sessions_expire_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let url = std::env::var("TACENTA_TEST_DATABASE_URL").unwrap();

    let (tenant, _key) = store
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    store
        .sign_up_user(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let (_, token) = store
        .sign_in(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();

    // A fresh session validates.
    assert!(
        store
            .validate_session(token.as_str())
            .await
            .unwrap()
            .is_some()
    );

    // Backdate the (only) session's expiry directly, then it no longer
    // validates — exactly as an unknown token does. (The database clock cannot
    // be fast-forwarded, so the row is moved into the past instead.)
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::query("update sessions set expires_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.validate_session(token.as_str()).await.unwrap(),
        None,
        "an expired session must not validate"
    );
}

#[tokio::test]
async fn sessions_can_be_revoked_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };

    let (tenant, _key) = store
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    for name in ["alice", "bob"] {
        store
            .sign_up_user(&tenant.id, name, "hunter2!!")
            .await
            .unwrap();
    }
    // Alice on two devices, Bob on one.
    let (_, a1) = store
        .sign_in(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let (_, a2) = store
        .sign_in(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let (_, b1) = store.sign_in(&tenant.id, "bob", "hunter2!!").await.unwrap();

    // Revoke one of Alice's sessions: it stops validating, her other stays.
    assert!(store.revoke_session(a1.as_str()).await.unwrap());
    assert!(store.validate_session(a1.as_str()).await.unwrap().is_none());
    assert!(store.validate_session(a2.as_str()).await.unwrap().is_some());
    // Revoking it again removes nothing.
    assert!(!store.revoke_session(a1.as_str()).await.unwrap());

    // Sign Alice out everywhere: her remaining session goes, Bob's is intact.
    assert_eq!(
        store
            .revoke_user_sessions(&tenant.id, "alice")
            .await
            .unwrap(),
        1
    );
    assert!(store.validate_session(a2.as_str()).await.unwrap().is_none());
    assert!(store.validate_session(b1.as_str()).await.unwrap().is_some());
}

#[tokio::test]
async fn sweep_removes_expired_sessions_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let url = std::env::var("TACENTA_TEST_DATABASE_URL").unwrap();

    let (tenant, _key) = store
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    store
        .sign_up_user(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    store
        .sign_up_user(&tenant.id, "bob", "hunter2!!")
        .await
        .unwrap();
    let (_, live) = store
        .sign_in(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let (_, doomed) = store.sign_in(&tenant.id, "bob", "hunter2!!").await.unwrap();

    // Backdate only bob's session, then sweep: exactly it is removed, alice's
    // stays, and the row is actually gone (a re-sweep removes nothing).
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let doomed_hash = {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::digest(doomed.as_str().as_bytes()).into();
        d
    };
    sqlx::query("update sessions set expires_at = now() - interval '1 hour' where token_hash = $1")
        .bind(&doomed_hash[..])
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(store.sweep_expired_sessions().await.unwrap(), 1);
    assert!(
        store
            .validate_session(live.as_str())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .validate_session(doomed.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.sweep_expired_sessions().await.unwrap(), 0);
}
