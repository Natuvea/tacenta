//! The server listeners are served under `ServeLimits`: a connection cap so a
//! flood is bounded, and an idle bound so a
//! client that connects to a request/response service and never speaks is
//! closed rather than left holding a slot. This drives both over a real
//! socket against the account service, which is request/response.

use std::sync::Arc;
use std::time::Duration;

use tacenta_accounts::{AccountResponse, AccountStore, Accounts};
use tacenta_transport::{
    AccountConnection, ServeLimits, account_server, serve_accounts_with_limits,
};
use tokio::net::TcpListener;

/// A cap of one: the second concurrent connection is closed at once, and
/// once the first is dropped a new one is served again.
#[tokio::test]
async fn the_connection_cap_bounds_concurrency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = account_server(Arc::new(AccountStore::memory(Accounts::new())));
    let limits = ServeLimits {
        max_connections: 1,
        ..ServeLimits::default()
    };
    tokio::spawn(serve_accounts_with_limits(listener, server, limits));

    // The first connection holds the only slot. It works.
    let mut first = AccountConnection::connect(addr).await.unwrap();
    let AccountResponse::TenantCreated { .. } = first
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };

    // A second connection is accepted at TCP but its slot is refused, so the
    // server closes it: the first request reads end-of-stream.
    let mut second = AccountConnection::connect(addr).await.unwrap();
    let refused = second
        .sign_up_tenant("beta", "admin@beta.example", "correct horse")
        .await;
    assert!(
        refused.is_err(),
        "the over-cap connection must be closed, not served"
    );

    // Free the slot; a fresh connection is served again.
    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut third = AccountConnection::connect(addr).await.unwrap();
    assert!(matches!(
        third
            .sign_up_tenant("gamma", "admin@gamma.example", "correct horse")
            .await
            .unwrap(),
        AccountResponse::TenantCreated { .. }
    ));
}

/// A client that connects and never sends is closed once the idle bound
/// passes, freeing its slot for another.
#[tokio::test]
async fn an_idle_client_is_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = account_server(Arc::new(AccountStore::memory(Accounts::new())));
    let limits = ServeLimits {
        max_connections: 1,
        idle: Duration::from_millis(150),
        ..ServeLimits::default()
    };
    tokio::spawn(serve_accounts_with_limits(listener, server, limits));

    // Connect and say nothing: the account service writes nothing on connect
    // and waits for a request, so the server closes the connection after the
    // idle bound and frees the slot.
    let idle = AccountConnection::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    drop(idle);

    // The slot is free again: a normal client is served.
    let mut ok = AccountConnection::connect(addr).await.unwrap();
    assert!(matches!(
        ok.sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .await
            .unwrap(),
        AccountResponse::TenantCreated { .. }
    ));
}
