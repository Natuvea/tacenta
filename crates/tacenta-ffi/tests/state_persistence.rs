//! A foreign caller resumes a *live ratchet* across a restart.
//!
//! The bindings expose `exportIdentity`/`signInWithIdentity`, which restore
//! who you are while every ratchet starts again from nothing, and the state
//! form, `exportState`/`signInWithState`, which restores the ratchets too --
//! the pair the Rust client carries as `export_state`/`connect_with_state`
//! (decision 0051). A Swift or Kotlin app resumes a conversation through the
//! state form, so the state form is what this covers.
//!
//! The test is written so it would fail without it: it establishes
//! a session, exports, drops the client, restores from the exported bytes, and
//! then continues the *existing* conversation in both directions.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_ffi::{Client, Config};
use tacenta_server::{Config as ServerConfig, Server};

#[test]
fn a_binding_client_resumes_a_live_session_from_exported_state() {
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

    let cfg = |user: &str| Config {
        directory: directory.to_string(),
        relay: relay.to_string(),
        user: user.into(),
        device: 1,
    };

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let alice = Client::connect(cfg("+alice")).await.unwrap();
        let bob = Client::connect(cfg("+bob")).await.unwrap();
        let bob_addr = bob.address();
        let alice_addr = alice.address();

        // A real session: not just an identity, a ratchet that has advanced.
        alice
            .send(bob_addr.clone(), b"first".to_vec())
            .await
            .unwrap();
        assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"first");

        // Export, then let the client go entirely.
        let saved = alice.export_state().await.unwrap();
        assert!(!saved.is_empty(), "exported state must carry something");
        drop(alice);

        // A fresh process would do exactly this.
        let alice_again = Client::connect_with_state(cfg("+alice"), saved)
            .await
            .unwrap();
        assert_eq!(
            alice_again.address().user,
            alice_addr.user,
            "the restored client is the same party"
        );

        // **The point of the test**: the conversation continues rather than
        // restarting. Both directions, because a ratchet restored on one side only
        // would still pass a send-only check.
        alice_again
            .send(bob_addr, b"after restart".to_vec())
            .await
            .unwrap();
        let inbox = bob.receive().await.unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"after restart");

        bob.send(alice_addr, b"and back".to_vec()).await.unwrap();
        let reply = alice_again.receive().await.unwrap();
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].plaintext, b"and back");
    });

    // Keep the server runtime alive through the assertions.
    drop(server_rt);
}
