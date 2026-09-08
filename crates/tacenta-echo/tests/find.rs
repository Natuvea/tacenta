//! A user finds the echo bot by name, adds it as a contact, and messages it —
//! the whole discovery-to-conversation path. The bot runs as an account user
//! (`acme/echo`), so it is findable within the tenant like any other user.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_accounts::AccountResponse;
use tacenta_client::{AccountConfig, Contacts, DefaultClient, DeviceAddr};
use tacenta_echo::EchoBot;
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;

#[tokio::test]
async fn a_user_finds_the_echo_bot_and_messages_it() {
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

    // A tenant with two accounts: the echo bot, and alice.
    let mut admin = AccountConnection::connect(accounts).await.unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = admin
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };
    DefaultClient::sign_up(accounts, &api_key, "echo", "hunter2!!")
        .await
        .unwrap();
    DefaultClient::sign_up(accounts, &api_key, "alice", "hunter2!!")
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

    // The echo bot signs in and provisions as acme/echo.
    let mut bot = EchoBot::sign_in(&cfg("echo")).await.unwrap();

    // Alice signs in, finds the bot by name, and adds it as a contact.
    let mut alice = DefaultClient::sign_in(&cfg("alice")).await.unwrap();
    let contact = alice
        .find("echo")
        .await
        .unwrap()
        .expect("the echo bot is findable in the tenant");
    assert_eq!(contact.handle(), "acme/echo");

    let mut contacts = Contacts::new();
    contacts.add(contact.clone());
    assert!(contacts.get("acme/echo").is_some());

    // Alice messages the bot via the saved contact; the bot echoes it back.
    alice.send(&contact.address, b"hello, echo").await.unwrap();
    assert_eq!(bot.serve_once().await.unwrap(), 1);
    let inbox = alice.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, DeviceAddr::new("acme/echo", 1));
    assert_eq!(inbox[0].plaintext, b"hello, echo");

    // A user who does not exist resolves to nothing — no enumeration, just a
    // clean "not found".
    assert!(alice.find("nobody").await.unwrap().is_none());

    // The contact list survives a serialize/restore round trip (client-local
    // persistence).
    let restored = Contacts::from_bytes(&contacts.to_bytes()).unwrap();
    assert_eq!(restored.all(), contacts.all());
}
