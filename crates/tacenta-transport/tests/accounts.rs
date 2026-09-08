//! The account service over a socket: create a tenant, create a user under it,
//! and sign in — plus the coarse refusals for a wrong password, a duplicate
//! user, and a bad API key.

use std::sync::Arc;

use tacenta_accounts::{AccountResponse, AccountStore, Accounts, SignupReason};
use tacenta_transport::{AccountConnection, account_server, serve_accounts};

async fn start() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = account_server(Arc::new(AccountStore::memory(Accounts::new())));
    tokio::spawn(serve_accounts(listener, server));
    addr
}

#[tokio::test]
async fn signup_and_signin_over_a_socket() {
    let addr = start().await;
    let mut conn = AccountConnection::connect(addr).await.unwrap();

    // Create a tenant and capture its one-time API key.
    let AccountResponse::TenantCreated { api_key, .. } = conn
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant to be created");
    };

    // Create a user under that tenant.
    assert_eq!(
        conn.sign_up_user(&api_key, "alice", "hunter2!!")
            .await
            .unwrap(),
        AccountResponse::UserCreated {
            username: "alice".into()
        },
    );

    // Sign in by username returns the handle and a session token.
    let by_name = conn.sign_in(&api_key, "alice", "hunter2!!").await.unwrap();
    let AccountResponse::SignedIn { username, token } = by_name else {
        panic!("expected a signed-in response");
    };
    assert_eq!(username, "alice");
    assert!(token.starts_with("ses_"), "a session token is issued");

    // A wrong password is a coarse refusal — no account-existence leak.
    assert_eq!(
        conn.sign_in(&api_key, "alice", "wrong").await.unwrap(),
        AccountResponse::SignInRefused,
    );

    // A duplicate username comes back as a coarse signup reason.
    assert_eq!(
        conn.sign_up_user(&api_key, "alice", "hunter2!!")
            .await
            .unwrap(),
        AccountResponse::SignupRefused {
            reason: SignupReason::UsernameTaken
        },
    );

    // A bad API key selects no tenant.
    assert_eq!(
        conn.sign_up_user("tct_bogus", "bob", "hunter2!!")
            .await
            .unwrap(),
        AccountResponse::UnknownTenant,
    );
}
