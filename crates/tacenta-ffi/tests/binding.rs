//! The binding drives a conversation exactly as a Swift/Kotlin caller
//! would: construct a `Client`, `send`, `receive`, awaiting each as the
//! generated `async`/`suspend` surface does. Exercises the exported UniFFI
//! surface from Rust.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_ffi::{Client, Config};
use tacenta_server::{Config as ServerConfig, Server};

#[test]
fn the_binding_drives_a_conversation() {
    // Run the server on its own runtime, serving in the background.
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
    server_rt.spawn(server.serve());

    // The clients, awaited as a foreign caller's generated surface does.
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let alice = Client::connect(Config {
            directory: directory.to_string(),
            relay: relay.to_string(),
            user: "+alice".into(),
            device: 1,
        })
        .await
        .unwrap();
        let bob = Client::connect(Config {
            directory: directory.to_string(),
            relay: relay.to_string(),
            user: "+bob".into(),
            device: 1,
        })
        .await
        .unwrap();

        let bob_addr = bob.address();
        alice
            .send(bob_addr, b"hello over the binding".to_vec())
            .await
            .unwrap();

        let inbox = bob.receive().await.unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from.user, "+alice");
        assert_eq!(inbox[0].plaintext, b"hello over the binding");
    });

    // Keep the server runtime alive through the assertions.
    drop(server_rt);
}
