//! End-to-end sign-in rate limiting through the real `Accounts` store.
//!
//! Uses `sign_in_at` with an explicit clock so the sliding window is exercised
//! deterministically, no wall-clock dependence. argon2 makes each *failed*
//! attempt costly, so the traces are deliberately short.

use tacenta_accounts::{Accounts, AuthError};

const PASSWORD: &str = "correct-horse-battery";
const WRONG: &str = "not-the-password";
const WINDOW: u64 = 60; // matches ratelimit::WINDOW_SECS

fn setup() -> (Accounts, tacenta_accounts::TenantId) {
    let mut accounts = Accounts::new();
    let (tenant, _key) = accounts
        .sign_up_tenant("acme", "acme@example.com", PASSWORD)
        .expect("tenant signup");
    accounts
        .sign_up_user(&tenant.id, "alice", PASSWORD)
        .expect("user signup");
    let id = tenant.id;
    (accounts, id)
}

#[test]
fn five_failures_then_the_next_attempt_is_blocked_even_with_the_right_password() {
    let (mut accounts, tenant) = setup();

    // Five wrong passwords at t=0 each fail with InvalidCredentials.
    for _ in 0..5 {
        assert_eq!(
            accounts.sign_in_at(0, &tenant, "alice", WRONG).err(),
            Some(AuthError::InvalidCredentials)
        );
    }

    // The sixth attempt is refused as rate-limited — and crucially, even the
    // *correct* password is refused while blocked, so guessing gains nothing by
    // eventually hitting it.
    assert_eq!(
        accounts.sign_in_at(0, &tenant, "alice", PASSWORD).err(),
        Some(AuthError::RateLimited)
    );
}

#[test]
fn the_block_lifts_after_the_window() {
    let (mut accounts, tenant) = setup();
    for _ in 0..5 {
        let _ = accounts.sign_in_at(0, &tenant, "alice", WRONG);
    }
    assert_eq!(
        accounts.sign_in_at(0, &tenant, "alice", PASSWORD).err(),
        Some(AuthError::RateLimited)
    );

    // Once the five failures have aged past the window, the correct password
    // is accepted again.
    assert!(
        accounts
            .sign_in_at(WINDOW + 1, &tenant, "alice", PASSWORD)
            .is_ok()
    );
}

#[test]
fn a_success_before_the_ceiling_clears_the_count() {
    let (mut accounts, tenant) = setup();

    // Four wrong tries, then the honest user types it right.
    for _ in 0..4 {
        let _ = accounts.sign_in_at(0, &tenant, "alice", WRONG);
    }
    assert!(accounts.sign_in_at(0, &tenant, "alice", PASSWORD).is_ok());

    // The successful sign-in cleared the failures, so a later slip is not
    // immediately one-away-from-blocked: four more wrong tries still do not
    // block, proving the counter reset.
    for _ in 0..4 {
        assert_eq!(
            accounts.sign_in_at(0, &tenant, "alice", WRONG).err(),
            Some(AuthError::InvalidCredentials)
        );
    }
}

#[test]
fn throttling_a_missing_account_does_not_reveal_it_and_does_not_lock_others() {
    let (mut accounts, tenant) = setup();

    // A non-existent identifier throttles just like a real one — same errors,
    // same ceiling — so blocking is no account-existence oracle.
    for _ in 0..5 {
        assert_eq!(
            accounts.sign_in_at(0, &tenant, "ghost", WRONG).err(),
            Some(AuthError::InvalidCredentials)
        );
    }
    assert_eq!(
        accounts.sign_in_at(0, &tenant, "ghost", WRONG).err(),
        Some(AuthError::RateLimited)
    );

    // Locking "ghost" does not lock the real user — keys are independent.
    assert!(accounts.sign_in_at(0, &tenant, "alice", PASSWORD).is_ok());
}
