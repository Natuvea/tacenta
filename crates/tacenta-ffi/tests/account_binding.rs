//! The binding drives the account flow as a Swift/Kotlin caller would: sign up
//! a user, sign in (which provisions the device), find another user, and
//! message them by handle, awaiting each as the generated surface does.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_accounts::AccountResponse;
use tacenta_ffi::{AccountConfig, Client, sign_up};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;

#[test]
fn the_binding_drives_the_account_flow() {
    let server_rt = tokio::runtime::Runtime::new().unwrap();
    let server = server_rt
        .block_on(Server::bind(&ServerConfig {
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
        }))
        .unwrap();
    let directory = server.directory_addr().unwrap();
    let relay = server.relay_addr().unwrap();
    let accounts = server.accounts_addr().unwrap();
    let provisioning = server.provisioning_addr().unwrap();
    server_rt.spawn(server.serve());

    // Create a tenant (admin) on the server runtime, capturing its API key.
    let api_key = server_rt.block_on(async {
        let mut admin = AccountConnection::connect(accounts).await.unwrap();
        let AccountResponse::TenantCreated { api_key, .. } = admin
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .await
            .unwrap()
        else {
            panic!("expected a tenant");
        };
        api_key
    });

    let acct = |identifier: &str| AccountConfig {
        directory: directory.to_string(),
        relay: relay.to_string(),
        accounts: accounts.to_string(),
        provisioning: provisioning.to_string(),
        identifier: identifier.into(),
        device: 1,
    };

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        // Sign up two users through the binding's free function.
        sign_up(
            accounts.to_string(),
            api_key.clone(),
            "alice".into(),
            "hunter2!!".into(),
        )
        .await
        .unwrap();
        sign_up(
            accounts.to_string(),
            api_key.clone(),
            "bob".into(),
            "hunter2!!".into(),
        )
        .await
        .unwrap();

        // Sign in: provisions each device under its account handle.
        let alice = Client::sign_in(acct("alice"), api_key.clone(), "hunter2!!".into())
            .await
            .unwrap();
        let bob = Client::sign_in(acct("bob"), api_key.clone(), "hunter2!!".into())
            .await
            .unwrap();
        assert_eq!(alice.address().user, "acme/alice");

        // Alice finds Bob by name and messages him by his handle.
        let contact = alice
            .find("bob".into())
            .await
            .unwrap()
            .expect("bob is findable");
        assert_eq!(contact.address.user, "acme/bob");
        alice
            .send(contact.address, b"hello over the account binding".to_vec())
            .await
            .unwrap();

        let inbox = bob.receive().await.unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from.user, "acme/alice");
        assert_eq!(inbox[0].plaintext, b"hello over the account binding");

        // A user who does not exist resolves to none.
        assert!(alice.find("nobody".into()).await.unwrap().is_none());
    });

    // Keep the server runtime alive through the assertions.
    drop(server_rt);
}
