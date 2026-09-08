//! Dudect-style empirical constant-time check on the authentication path.
//!
//! `authenticate_user` must not leak, through its timing, whether an account
//! exists: a wrong password against a *real* account and any password against
//! a *missing* account both return `InvalidCredentials`, and both must take
//! the same time. The defense is the dummy-verify in `authenticate_user` — a
//! missing account still runs one `argon2` verify against `dummy_hash()`,
//! which is produced by the same `hash_password` (same argon2 params) as a
//! real account, so the two paths do identical work.
//!
//! This test measures it, in the style of dudect (Reparaz/Balasch/
//! Verbauwhede): time the two input classes, interleaved, crop scheduler
//! outliers, and compute Welch's t-statistic. A large |t| is evidence the two
//! classes are distinguishable by timing — i.e. a leak. It is a *measurement*,
//! not a proof of constant-timeness, and argon2 itself is not constant-time
//! (it does not need to be — the same operation runs either way); what is
//! asserted is only that removing the equalizing dummy-verify would be caught.
//!
//! `#[ignore]` because wall-clock timing is environment-sensitive and would
//! make CI flaky; run explicitly with:
//!   cargo test -p tacenta-accounts --test timing -- --ignored --nocapture

use std::time::Instant;
use tacenta_accounts::Accounts;

const PASSWORD: &str = "correct-horse-battery";
const WRONG: &str = "not-the-password-at-all";

/// Welch's t-statistic between two samples (unequal variance).
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var =
        |x: &[f64], m: f64| x.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (x.len() as f64 - 1.0);
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    let se = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if se == 0.0 { 0.0 } else { (ma - mb) / se }
}

/// Drop the slowest `frac` of samples — those are OS-scheduler / page-fault
/// outliers, not signal, and dudect crops similarly before its t-test.
fn crop_slowest(mut xs: Vec<f64>, frac: f64) -> Vec<f64> {
    xs.sort_by(|p, q| p.partial_cmp(q).unwrap());
    let keep = ((xs.len() as f64) * (1.0 - frac)) as usize;
    xs.truncate(keep.max(2));
    xs
}

#[test]
#[ignore = "timing-sensitive; run with --ignored"]
fn authenticate_does_not_leak_account_existence_by_timing() {
    let mut accounts = Accounts::new();
    let (tenant, _key) = accounts
        .sign_up_tenant("acme", "acme@example.com", PASSWORD)
        .expect("tenant signup");
    accounts
        .sign_up_user(&tenant.id, "alice", PASSWORD)
        .expect("user signup");

    // Warm up: force `dummy_hash()`'s one-time init and prime argon2 code
    // paths / caches so the first measured sample is not an outlier.
    for _ in 0..8 {
        let _ = accounts.authenticate_user(&tenant.id, "alice", WRONG);
        let _ = accounts.authenticate_user(&tenant.id, "ghost", WRONG);
    }

    // Interleave the two classes so any slow drift in the machine hits both
    // equally rather than biasing one class.
    const N: usize = 120;
    let mut existing = Vec::with_capacity(N); // real account, wrong password
    let mut missing = Vec::with_capacity(N); // no such account
    for _ in 0..N {
        let t0 = Instant::now();
        let r1 = accounts.authenticate_user(&tenant.id, "alice", WRONG);
        existing.push(t0.elapsed().as_secs_f64());

        let t1 = Instant::now();
        let r2 = accounts.authenticate_user(&tenant.id, "ghost", WRONG);
        missing.push(t1.elapsed().as_secs_f64());

        // Both must actually fail — otherwise we would be timing different
        // outcomes, not the existence oracle.
        assert!(r1.is_err() && r2.is_err());
    }

    let existing = crop_slowest(existing, 0.10);
    let missing = crop_slowest(missing, 0.10);
    let t = welch_t(&existing, &missing);

    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    eprintln!(
        "existing-account mean: {:.1}us   missing-account mean: {:.1}us   Welch t = {:.2}",
        mean(&existing) * 1e6,
        mean(&missing) * 1e6,
        t,
    );

    // A loose regression bound: identical work on both paths keeps |t| small;
    // deleting the dummy-verify (so a missing account skips argon2 entirely)
    // moves the missing-account mean by ~an argon2 verify and sends |t| far
    // past this. The bound is generous so ordinary wall-clock noise on an
    // ~argon2-dominated measurement does not trip it. This is a smoke check,
    // not a rigorous constant-time proof.
    assert!(
        t.abs() < 12.0,
        "auth timing distinguishes existing vs missing accounts (Welch t = {t:.2}); \
         the dummy-verify may have regressed"
    );
}
