//! Spec-conformance property tests for tenant isolation.
//!
//! `spec/Tacenta/Accounts.lean` proves that the user map is keyed by
//! `(tenant, username)`: a signup binds its key (`signUp_binds`), refuses a
//! taken one (`signUp_rejects_taken`), leaves every other key untouched
//! (`signUp_frames`), and the same username lives in two tenants
//! independently (`tenant_isolation`). Those proofs are about the abstract
//! Lean model. This file is the empirical bridge to the shipped Rust: it
//! drives the real `Accounts` store and checks the same four properties over
//! randomized signup traces, plus a differential model check against a
//! reference keyed exactly as the spec is.
//!
//! Inputs are held always-valid (fixed strong password, valid usernames) so
//! the only thing that varies is the `(tenant, username)` key collision the
//! isolation property is about. argon2id hashing makes each fresh signup
//! costly, so traces are kept small — collisions short-circuit before hashing.

use std::collections::HashSet;
use tacenta_accounts::{Accounts, AuthError, SignupError, TenantId};

/// Deterministic LCG (glibc constants), matching the crate convention.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const PASSWORD: &str = "correct-horse-battery";
const USERNAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

/// Stand up `n` tenants and return their ids. Each tenant is itself a unique
/// signup (unique tenant username/email), independent of the user space.
fn make_tenants(accounts: &mut Accounts, n: usize) -> Vec<TenantId> {
    (0..n)
        .map(|i| {
            let (tenant, _key) = accounts
                .sign_up_tenant(
                    &format!("tenant{i}"),
                    &format!("tenant{i}@example.com"),
                    PASSWORD,
                )
                .expect("tenant signup should succeed");
            tenant.id
        })
        .collect()
}

#[test]
fn same_username_lives_in_two_tenants_independently() {
    // `tenant_isolation` on the real store: the same username signs up
    // successfully in two different tenants, and each resolves to its own
    // handle without disturbing the other.
    let mut accounts = Accounts::new();
    let tenants = make_tenants(&mut accounts, 2);

    let a = accounts
        .sign_up_user(&tenants[0], "alice", PASSWORD)
        .expect("alice in tenant 0");
    let b = accounts
        .sign_up_user(&tenants[1], "alice", PASSWORD)
        .expect("alice in tenant 1 must also succeed — usernames are per-tenant");

    assert_eq!(a.tenant, tenants[0]);
    assert_eq!(b.tenant, tenants[1]);
    assert_ne!(a.tenant, b.tenant);

    // The account layer maps each per-tenant identity onto a distinct
    // directory handle: `tenant0/alice` vs `tenant1/alice`. Same username,
    // two independent addresses.
    assert_eq!(
        accounts.handle(&tenants[0], "alice"),
        Some("tenant0/alice".to_string())
    );
    assert_eq!(
        accounts.handle(&tenants[1], "alice"),
        Some("tenant1/alice".to_string())
    );

    // Both users genuinely exist and authenticate independently.
    assert!(
        accounts
            .authenticate_user(&tenants[0], "alice", PASSWORD)
            .is_ok()
    );
    assert!(
        accounts
            .authenticate_user(&tenants[1], "alice", PASSWORD)
            .is_ok()
    );

    // A second alice in tenant 0 is refused (the key is taken there), and
    // that refusal does not touch tenant 1's alice.
    assert_eq!(
        accounts.sign_up_user(&tenants[0], "alice", PASSWORD),
        Err(SignupError::UsernameTaken)
    );
    assert!(
        accounts
            .authenticate_user(&tenants[1], "alice", PASSWORD)
            .is_ok()
    );
}

#[test]
fn signup_binds_rejects_and_frames_on_rust() {
    // A differential trace: random `sign_up_user` over a small
    // `(tenant, username)` space against the real store and a reference set
    // model keyed the way the spec is. Every signup outcome must match the
    // model — a fresh key binds (`signUp_binds`), a taken one is refused
    // (`signUp_rejects_taken`), and because the model is keyed by
    // `(tenant, username)`, a username taken in one tenant staying free in
    // another is exactly `signUp_frames` + `tenant_isolation`. Then, once per
    // trace (argon2 is costly), every model member is confirmed to actually
    // exist and every non-member confirmed absent — the positive form of the
    // binding, not just the collision signal.
    for seed in 0..8u64 {
        let mut accounts = Accounts::new();
        let tenants = make_tenants(&mut accounts, 3);
        let mut model: HashSet<(usize, &str)> = HashSet::new();
        let mut rng = Lcg(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1));

        for _ in 0..30 {
            let t_idx = rng.below(tenants.len() as u64) as usize;
            let uname = USERNAMES[rng.below(USERNAMES.len() as u64) as usize];

            let out = accounts.sign_up_user(&tenants[t_idx], uname, PASSWORD);

            // Outcome: fresh key binds, taken key is refused.
            if model.contains(&(t_idx, uname)) {
                assert_eq!(
                    out,
                    Err(SignupError::UsernameTaken),
                    "a taken key must be refused (seed {seed}, tenant {t_idx}, {uname})"
                );
            } else {
                assert!(
                    out.is_ok(),
                    "a fresh key must bind (seed {seed}, tenant {t_idx}, {uname}): {out:?}"
                );
                model.insert((t_idx, uname));
            }
        }

        // Positive existence: every `(tenant, username)` the model recorded
        // authenticates (it was really bound); every one it did not is absent
        // (framing held — no op ever bound a key it should not have).
        for (ti, tid) in tenants.iter().enumerate() {
            for &u in &USERNAMES {
                let auth = accounts.authenticate_user(tid, u, PASSWORD);
                if model.contains(&(ti, u)) {
                    assert!(
                        auth.is_ok(),
                        "model says bound but store denies it (seed {seed}, tenant {ti}, {u})"
                    );
                } else {
                    assert_eq!(
                        auth,
                        Err(AuthError::InvalidCredentials),
                        "model says absent but store has it (seed {seed}, tenant {ti}, {u})"
                    );
                }
            }
        }
    }
}
