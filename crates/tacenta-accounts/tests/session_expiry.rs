//! Session tokens expire after a fixed lifetime.
//!
//! A leaked or stolen session token is otherwise valid forever; a TTL bounds
//! the window. Exercised deterministically via the explicit-clock variants
//! (`sign_in_at` sets the expiry from its `now`, `validate_session_at` checks
//! against its `now`).

use tacenta_accounts::Accounts;

const PASSWORD: &str = "correct-horse-battery";
const TTL: u64 = 24 * 60 * 60; // matches SESSION_TTL_SECS

fn signed_in_at(now: u64) -> (Accounts, tacenta_accounts::TenantId, String) {
    let mut accounts = Accounts::new();
    let (tenant, _key) = accounts
        .sign_up_tenant("acme", "acme@example.com", PASSWORD)
        .expect("tenant signup");
    accounts
        .sign_up_user(&tenant.id, "alice", PASSWORD)
        .expect("user signup");
    let (_user, token) = accounts
        .sign_in_at(now, &tenant.id, "alice", PASSWORD)
        .expect("sign in");
    let id = tenant.id;
    (accounts, id, token.as_str().to_string())
}

#[test]
fn a_session_is_valid_until_its_ttl_then_expires() {
    let issued = 1_000_000u64;
    let (accounts, tenant, token) = signed_in_at(issued);

    // Valid at issue time and right up to (but not including) the TTL boundary.
    assert_eq!(
        accounts.validate_session_at(issued, &token),
        Some((tenant.clone(), "alice".to_string()))
    );
    assert_eq!(
        accounts.validate_session_at(issued + TTL - 1, &token),
        Some((tenant.clone(), "alice".to_string()))
    );

    // At and after the TTL boundary, the token authorises nothing.
    assert_eq!(accounts.validate_session_at(issued + TTL, &token), None);
    assert_eq!(
        accounts.validate_session_at(issued + TTL + 10_000, &token),
        None
    );
}

#[test]
fn an_unknown_token_never_validates() {
    let (accounts, _tenant, _token) = signed_in_at(0);
    assert_eq!(
        accounts.validate_session_at(0, "ses_not-a-real-token"),
        None
    );
}

#[test]
fn a_fresh_sign_in_issues_a_token_valid_for_the_full_ttl_from_then() {
    // Sign in far in the future; the new token is valid from that point, not
    // from the epoch — expiry is measured from issue time.
    let later = 5_000_000u64;
    let (accounts, tenant, token) = signed_in_at(later);
    assert_eq!(
        accounts.validate_session_at(later + TTL - 1, &token),
        Some((tenant, "alice".to_string()))
    );
    assert_eq!(accounts.validate_session_at(later + TTL, &token), None);
}

#[test]
fn sweeping_drops_only_expired_sessions() {
    // Two users sign in at t=0 (expire at TTL); a third signs in far later so
    // its session outlives a sweep run at just past the first TTL.
    let mut accounts = Accounts::new();
    let (tenant, _key) = accounts
        .sign_up_tenant("acme", "acme@example.com", PASSWORD)
        .unwrap();
    for n in ["alice", "bob", "carol"] {
        accounts.sign_up_user(&tenant.id, n, PASSWORD).unwrap();
    }
    let a = accounts
        .sign_in_at(0, &tenant.id, "alice", PASSWORD)
        .unwrap()
        .1;
    let _b = accounts
        .sign_in_at(0, &tenant.id, "bob", PASSWORD)
        .unwrap()
        .1;
    let c = accounts
        .sign_in_at(TTL, &tenant.id, "carol", PASSWORD)
        .unwrap()
        .1;

    // Just past the first TTL, alice's and bob's are expired; carol's is not.
    let removed = accounts.sweep_expired_sessions_at(TTL + 1);
    assert_eq!(removed, 2, "the two t=0 sessions should be swept");
    // Carol's still validates; a re-sweep removes nothing more.
    assert!(accounts.validate_session_at(TTL + 1, c.as_str()).is_some());
    assert_eq!(accounts.sweep_expired_sessions_at(TTL + 1), 0);
    // The swept token was already invalid and stays so.
    assert!(accounts.validate_session_at(TTL + 1, a.as_str()).is_none());
}
