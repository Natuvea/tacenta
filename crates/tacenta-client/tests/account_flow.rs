//! The account-based client flow end to end: two users under a tenant sign up,
//! sign in — which provisions their devices — and message each other by their
//! account handles, `acme/alice` and `acme/bob`.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_accounts::AccountResponse;
use tacenta_client::{AccountConfig, DefaultClient, DeviceAddr, Error};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;

#[tokio::test]
async fn two_users_message_by_handle() {
    let server = Server::bind(&ServerConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: None,
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    })
    .await
    .unwrap();
    let directory = server.directory_addr().unwrap();
    let relay = server.relay_addr().unwrap();
    let accounts = server.accounts_addr().unwrap();
    let provisioning = server.provisioning_addr().unwrap();
    tokio::spawn(server.serve());

    // Create the tenant (admin) and capture its API key.
    let mut admin = AccountConnection::connect(accounts).await.unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = admin
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };

    // Sign up two users under the tenant, through the facade.
    DefaultClient::sign_up(accounts, &api_key, "alice", "hunter2!!")
        .await
        .unwrap();
    DefaultClient::sign_up(accounts, &api_key, "bob", "hunter2!!")
        .await
        .unwrap();

    let cfg = |identifier: &str| AccountConfig {
        directory,
        relay,
        accounts,
        provisioning,
        api_key: api_key.clone(),
        identifier: identifier.into(),
        password: "hunter2!!".into(),
        device: 1,
    };

    // Sign in (which provisions each device) — the client operates under its
    // account handle.
    let mut alice = DefaultClient::sign_in(&cfg("alice")).await.unwrap();
    let mut bob = DefaultClient::sign_in(&cfg("bob")).await.unwrap();
    assert_eq!(alice.address(), &DeviceAddr::new("acme/alice", 1));
    let alice_addr = alice.address().clone();
    let bob_addr = bob.address().clone();
    assert_eq!(bob_addr, DeviceAddr::new("acme/bob", 1));

    // Alice messages Bob by his handle; Bob receives it, attributed to Alice's
    // handle — a first contact, no prior session.
    alice
        .send(&bob_addr, b"meet at the north dock")
        .await
        .unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, alice_addr);
    assert_eq!(inbox[0].plaintext, b"meet at the north dock");

    // Bob replies; Alice receives it.
    bob.send(&alice_addr, b"on my way").await.unwrap();
    let back = alice.receive().await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].plaintext, b"on my way");

    // A wrong password is refused, coarsely, before any provisioning.
    let bad = DefaultClient::sign_in(&AccountConfig {
        password: "wrong".into(),
        ..cfg("alice")
    })
    .await;
    assert!(matches!(
        bad,
        Err(Error::Account(AccountResponse::SignInRefused)),
    ));
}
