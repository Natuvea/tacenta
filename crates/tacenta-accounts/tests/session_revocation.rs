//! Sessions can be revoked before their TTL — sign-out and compromise response.

use tacenta_accounts::{Accounts, TenantId};

const PASSWORD: &str = "correct-horse-battery";

fn store_with_two_users() -> (Accounts, TenantId) {
    let mut accounts = Accounts::new();
    let (tenant, _key) = accounts
        .sign_up_tenant("acme", "acme@example.com", PASSWORD)
        .expect("tenant signup");
    for name in ["alice", "bob"] {
        accounts
            .sign_up_user(&tenant.id, name, PASSWORD)
            .expect("user signup");
    }
    (accounts, tenant.id)
}

#[test]
fn revoking_a_session_stops_its_token_before_the_ttl() {
    let (mut accounts, tenant) = store_with_two_users();
    let (_user, token) = accounts
        .sign_in_at(1000, &tenant, "alice", PASSWORD)
        .expect("sign in");
    let token = token.as_str().to_string();

    // Valid, then revoked, then no longer valid — well within the TTL.
    assert!(accounts.validate_session_at(1000, &token).is_some());
    assert!(accounts.revoke_session(&token));
    assert!(accounts.validate_session_at(1000, &token).is_none());

    // Revoking again reports nothing was there to remove.
    assert!(!accounts.revoke_session(&token));
}

#[test]
fn revoke_user_sessions_invalidates_every_token_for_that_user_only() {
    let (mut accounts, tenant) = store_with_two_users();

    // Alice signs in on two devices; Bob on one.
    let a1 = accounts
        .sign_in_at(1000, &tenant, "alice", PASSWORD)
        .unwrap()
        .1;
    let a2 = accounts
        .sign_in_at(1000, &tenant, "alice", PASSWORD)
        .unwrap()
        .1;
    let b1 = accounts
        .sign_in_at(1000, &tenant, "bob", PASSWORD)
        .unwrap()
        .1;
    let (a1, a2, b1) = (
        a1.as_str().to_string(),
        a2.as_str().to_string(),
        b1.as_str().to_string(),
    );

    // Sign Alice out everywhere: both her tokens go, Bob's is untouched.
    assert_eq!(accounts.revoke_user_sessions(&tenant, "alice"), 2);
    assert!(accounts.validate_session_at(1000, &a1).is_none());
    assert!(accounts.validate_session_at(1000, &a2).is_none());
    assert!(accounts.validate_session_at(1000, &b1).is_some());

    // Revoking again removes nothing.
    assert_eq!(accounts.revoke_user_sessions(&tenant, "alice"), 0);
}

#[test]
fn a_fresh_sign_in_after_revocation_works() {
    let (mut accounts, tenant) = store_with_two_users();
    let token = accounts
        .sign_in_at(1000, &tenant, "alice", PASSWORD)
        .unwrap()
        .1;
    accounts.revoke_session(token.as_str());

    // Revocation does not lock the account; a new sign-in issues a live token.
    let fresh = accounts
        .sign_in_at(1000, &tenant, "alice", PASSWORD)
        .unwrap()
        .1;
    assert!(accounts.validate_session_at(1000, fresh.as_str()).is_some());
}
