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
use tacenta_accounts::{AuthError, DeviceInventory, InventoryError, SignupError};
use tacenta_core::crypto::groups::inventory::{
    DeviceBinding, GROUP_EPOCH_V1, binding_commitment, issuer_public_key,
};

/// An honest device identity key: the public key of a secret that repeats one
/// byte, which the core's identity-key rule admits. The store refuses a key that
/// fails the rule, so a byte repeated 32 times will not do.
fn honest_key(seed: u8) -> [u8; 32] {
    issuer_public_key(&[seed; 32])
}

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

    // A first device advances the durable inventory from its empty state;
    // stale predecessor generations are refused even after the state is read
    // back from PostgreSQL.
    assert_eq!(
        store.device_inventory(&tenant.id, "alice").await.unwrap(),
        Some(DeviceInventory::default()),
    );
    let binding = DeviceBinding {
        device_id: 1,
        identity_public_key: honest_key(7),
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: None,
    };
    let inventory = store
        .link_device_binding(&tenant.id, "alice", 0, [1; 32], binding.clone())
        .await
        .unwrap();
    assert_eq!(inventory.generation, 1);
    assert_eq!(
        store.device_inventory(&tenant.id, "alice").await.unwrap(),
        Some(inventory),
    );
    assert_eq!(
        store
            .link_device_binding(&tenant.id, "alice", 0, [1; 32], binding.clone())
            .await
            .unwrap()
            .generation,
        1,
        "the database keeps the original result for an idempotent retry"
    );
    assert!(matches!(
        store
            .link_device_binding(&tenant.id, "alice", 0, [2; 32], binding.clone())
            .await,
        Err(PgError::Inventory(InventoryError::PredecessorMismatch)),
    ));
    let replacement = DeviceBinding {
        device_id: 2,
        identity_public_key: honest_key(8),
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: Some(binding_commitment(&binding).unwrap()),
    };
    let replaced = store
        .replace_device_binding(
            &tenant.id,
            "alice",
            1,
            [3; 32],
            binding.clone(),
            replacement.clone(),
        )
        .await
        .unwrap();
    assert_eq!(replaced.generation, 2);
    assert_eq!(replaced.active, vec![replacement.clone()]);
    assert_eq!(
        store
            .replace_device_binding(
                &tenant.id,
                "alice",
                1,
                [3; 32],
                binding,
                replacement.clone(),
            )
            .await
            .unwrap(),
        replaced,
        "the database keeps the original replacement result for an exact retry"
    );
    let revoked = store
        .revoke_device_binding(&tenant.id, "alice", 2, [4; 32], replacement)
        .await
        .unwrap();
    assert_eq!(revoked.generation, 3);
    assert!(revoked.active.is_empty());

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

/// The race the mutation's lock-then-read-then-compare-and-set order exists to
/// settle, against the real database. Sixteen submitters race at generation 0,
/// each with its own retry key and a distinct binding. The predecessor
/// generation is a compare-and-set, so exactly one may win and the stored
/// inventory must hold exactly that winner's binding at generation 1.
///
/// The order itself is checked without a database by the interleaving tests in
/// `inventory_tx.rs`; this is the check that the SQL behaves as that model
/// assumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_links_at_one_predecessor_admit_exactly_one() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let store = std::sync::Arc::new(store);
    let (tenant, _) = store
        .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    store
        .sign_up_user(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for i in 1..=16u8 {
        let store = store.clone();
        let tenant = tenant.id.clone();
        tasks.push(tokio::spawn(async move {
            let binding = DeviceBinding {
                device_id: u32::from(i),
                identity_public_key: honest_key(i),
                capabilities: GROUP_EPOCH_V1,
                replacement_predecessor: None,
            };
            let result = store
                .link_device_binding(&tenant, "alice", 0, [i; 32], binding.clone())
                .await;
            (binding, result)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (binding, result) = task.await.unwrap();
        match result {
            Ok(inventory) => winners.push((binding, inventory)),
            Err(PgError::Inventory(InventoryError::PredecessorMismatch)) => {}
            Err(other) => panic!("unexpected refusal: {other:?}"),
        }
    }
    let stored = store
        .device_inventory(&tenant.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        winners.len(),
        1,
        "exactly one submitter may win generation 1"
    );
    assert_eq!(stored.generation, 1);
    assert_eq!(stored.active, vec![winners[0].0.clone()]);
}

/// The same race on an account that already has a stored row, so the write is
/// the guarded `update`, and mixing the three operations: links, plus a revoke
/// and a replace of the same active binding, all at generation 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mixed_mutations_at_one_predecessor_admit_exactly_one() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let store = std::sync::Arc::new(store);
    let (tenant, _) = store
        .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    store
        .sign_up_user(&tenant.id, "alice", "hunter2!!")
        .await
        .unwrap();
    let first = DeviceBinding {
        device_id: 100,
        identity_public_key: honest_key(100),
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: None,
    };
    store
        .link_device_binding(&tenant.id, "alice", 0, [100; 32], first.clone())
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for i in 1..=6u8 {
        let store = store.clone();
        let tenant = tenant.id.clone();
        let first = first.clone();
        tasks.push(tokio::spawn(async move {
            let other = DeviceBinding {
                device_id: u32::from(i),
                identity_public_key: honest_key(i),
                capabilities: GROUP_EPOCH_V1,
                replacement_predecessor: None,
            };
            match i % 3 {
                0 => {
                    store
                        .link_device_binding(&tenant, "alice", 1, [i; 32], other)
                        .await
                }
                1 => {
                    store
                        .revoke_device_binding(&tenant, "alice", 1, [i; 32], first)
                        .await
                }
                _ => {
                    let successor = DeviceBinding {
                        replacement_predecessor: Some(binding_commitment(&first).unwrap()),
                        ..other
                    };
                    store
                        .replace_device_binding(&tenant, "alice", 1, [i; 32], first, successor)
                        .await
                }
            }
        }));
    }
    let mut wins = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => wins += 1,
            Err(PgError::Inventory(InventoryError::PredecessorMismatch)) => {}
            Err(other) => panic!("unexpected refusal: {other:?}"),
        }
    }
    assert_eq!(wins, 1, "exactly one mutation may take generation 2");
    let stored = store
        .device_inventory(&tenant.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.generation, 2);
}

/// A refused retry (same key, different body) must be the typed conflict, must
/// not change state, and a cross-account use of the same key must not return
/// the first account's record.
#[tokio::test]
async fn idempotency_is_scoped_and_conflicts_are_typed_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let (tenant, _) = store
        .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    for name in ["alice", "bob"] {
        store
            .sign_up_user(&tenant.id, name, "hunter2!!")
            .await
            .unwrap();
    }
    let b = |id: u32, k: u8| DeviceBinding {
        device_id: id,
        identity_public_key: honest_key(k),
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: None,
    };
    let first = store
        .link_device_binding(&tenant.id, "alice", 0, [1; 32], b(1, 1))
        .await
        .unwrap();
    assert!(matches!(
        store
            .link_device_binding(&tenant.id, "alice", 0, [1; 32], b(2, 2))
            .await,
        Err(PgError::Inventory(InventoryError::IdempotencyConflict))
    ));
    assert!(matches!(
        store
            .revoke_device_binding(&tenant.id, "alice", 1, [1; 32], b(1, 1))
            .await,
        Err(PgError::Inventory(InventoryError::IdempotencyConflict))
    ));
    let bob = store
        .link_device_binding(&tenant.id, "bob", 0, [1; 32], b(7, 7))
        .await
        .unwrap();
    assert_ne!(bob, first);
    assert!(matches!(
        store
            .link_device_binding(&tenant.id, "mallory", 0, [1; 32], b(1, 1))
            .await,
        Err(PgError::Inventory(InventoryError::UnknownUser))
    ));
    assert_eq!(
        store.device_inventory(&tenant.id, "alice").await.unwrap(),
        Some(first)
    );
}

/// The handle a hosted inventory statement names is the directory's, which is
/// lower-case whatever spelling the caller used.
#[tokio::test]
async fn the_handle_uses_the_normalized_username_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let (tenant, _) = store
        .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    for spelling in ["alice", "Alice", " ALICE "] {
        assert_eq!(
            store.handle(&tenant.id, spelling).await.unwrap().as_deref(),
            Some("acme/alice"),
            "{spelling:?}"
        );
    }
}

/// The rules that keep an unsound binding out of a stored inventory hold on the
/// database path as well as in memory: nothing is stored, no retry key is used
/// up, and the same request is accepted once it is valid.
#[tokio::test]
async fn a_binding_the_rules_refuse_is_not_stored_on_postgres() {
    let _serial = db_serial();
    let Some(store) = store().await else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres tests");
        return;
    };
    let (tenant, _) = store
        .sign_up_tenant("Acme", "admin@acme.example", "correct horse")
        .await
        .unwrap();
    for user in ["alice", "bob"] {
        store
            .sign_up_user(&tenant.id, user, "hunter2!!")
            .await
            .unwrap();
    }
    let device = |device_id: u32, seed: u8| DeviceBinding {
        device_id,
        identity_public_key: honest_key(seed),
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: None,
    };
    let mut p_minus_1 = [0xffu8; 32];
    p_minus_1[0] = 0xec;
    p_minus_1[31] = 0x7f;
    let mut u_one = [0u8; 32];
    u_one[0] = 1;
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let listed_value: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];
    // A respelling of honest_key(7): the same key for X25519, other bytes.
    let respelling: [u8; 32] = [
        0x5a, 0xf8, 0x92, 0x2e, 0x95, 0xb3, 0x1b, 0x0d, 0x50, 0xd0, 0x2e, 0x68, 0x11, 0xe0, 0xc4,
        0xd8, 0xc7, 0xd7, 0x68, 0x66, 0xdf, 0xd9, 0x16, 0xd3, 0xce, 0x7c, 0x15, 0x1d, 0x9f, 0x36,
        0xad, 0x4d,
    ];
    let refused = [[0u8; 32], u_one, p_minus_1, p, listed_value, respelling];

    // Links with a key the rule refuses.
    for key in refused {
        let bad = DeviceBinding {
            identity_public_key: key,
            ..device(1, 1)
        };
        assert!(
            matches!(
                store
                    .link_device_binding(&tenant.id, "alice", 0, [1; 32], bad)
                    .await,
                Err(PgError::Inventory(InventoryError::IdentityKey(_)))
            ),
            "{key:02x?}"
        );
    }
    // A link that claims to replace a device: one never linked, and bob's.
    store
        .link_device_binding(&tenant.id, "bob", 0, [1; 32], device(5, 5))
        .await
        .unwrap();
    for named in [device(77, 77), device(5, 5)] {
        let forged = DeviceBinding {
            replacement_predecessor: Some(binding_commitment(&named).unwrap()),
            ..device(1, 1)
        };
        assert!(matches!(
            store
                .link_device_binding(&tenant.id, "alice", 0, [1; 32], forged)
                .await,
            Err(PgError::Inventory(
                InventoryError::UnexpectedReplacementPredecessor
            ))
        ));
    }
    assert_eq!(
        store.device_inventory(&tenant.id, "alice").await.unwrap(),
        Some(DeviceInventory::default()),
        "nothing was stored for alice"
    );

    // With one real device, a replacement whose key or marker is wrong.
    let first = device(1, 1);
    store
        .link_device_binding(&tenant.id, "alice", 0, [1; 32], first.clone())
        .await
        .unwrap();
    let stored = store.device_inventory(&tenant.id, "alice").await.unwrap();
    let with_marker = |of: &DeviceBinding, device_id: u32, seed: u8| DeviceBinding {
        replacement_predecessor: Some(binding_commitment(of).unwrap()),
        ..device(device_id, seed)
    };
    for key in refused {
        let replacement = DeviceBinding {
            identity_public_key: key,
            ..with_marker(&first, 2, 2)
        };
        assert!(matches!(
            store
                .replace_device_binding(&tenant.id, "alice", 1, [2; 32], first.clone(), replacement)
                .await,
            Err(PgError::Inventory(InventoryError::IdentityKey(_)))
        ));
    }
    for wrong in [
        device(2, 2),
        with_marker(&device(77, 77), 2, 2),
        with_marker(&device(5, 5), 2, 2),
    ] {
        assert!(matches!(
            store
                .replace_device_binding(&tenant.id, "alice", 1, [2; 32], first.clone(), wrong)
                .await,
            Err(PgError::Inventory(
                InventoryError::ReplacementPredecessorMismatch
            ))
        ));
    }
    assert_eq!(
        store.device_inventory(&tenant.id, "alice").await.unwrap(),
        stored,
        "no refused mutation changed the stored inventory"
    );

    // No retry key was used up: the right request now succeeds under each.
    let replaced = store
        .replace_device_binding(
            &tenant.id,
            "alice",
            1,
            [2; 32],
            first.clone(),
            with_marker(&first, 2, 2),
        )
        .await
        .unwrap();
    assert_eq!(replaced.generation, 2);
}
