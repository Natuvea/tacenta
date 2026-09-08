//! The relay's whole-node memory ceiling is reachable from server `Config`,
//! so a deployment can set it without patching the relay. This exercises the `Config::relay_max_total_bytes` wiring end to
//! end: a server built with a configured ceiling comes up and routes a message.
//!
//! It does *not* re-prove enforcement — driving total memory to the ceiling would
//! mean pushing ≥ `MAX_USER_BYTES` of traffic over sockets. Enforcement at the
//! ceiling is covered by `tacenta_relay`'s
//! `the_global_budget_bounds_the_whole_relay_across_users`; what this pins is that
//! the configured value actually reaches `Relay::with_max_total_bytes` and a
//! server built that way is healthy.

use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::{DeviceAddr, MAX_USER_BYTES};
use tacenta_server::{Config, Server};
use tacenta_transport::DirConnection;

#[tokio::test]
async fn a_configured_relay_ceiling_is_applied_and_the_server_serves() {
    // The minimum the setter allows — one user must still be able to reach their
    // own budget — set explicitly rather than left at the 4 GiB default.
    let config = Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: None,
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: Some(MAX_USER_BYTES as u64),
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };
    let server = Server::bind(&config).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    tokio::spawn(server.serve());

    // The server is healthy with the configured ceiling: a registration over the
    // directory succeeds.
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);
    let bundle = CryptoProvider::publish_bundle(&mut alice, &mut rng)
        .await
        .unwrap();
    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    let outcome = dir
        .register(
            &alice_r,
            CryptoProvider::identity_key(&alice),
            bundle,
            |ch| alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);
}
