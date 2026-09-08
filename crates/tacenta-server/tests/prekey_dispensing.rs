//! One-time prekeys are dispensed, not broadcast (decision record 0074).
//!
//! The whole path over a real socket: a device registers its multi-use bundle,
//! deposits a batch of one-time bundles, and successive lookups get *different*
//! ones until the pool empties and the multi-use bundle takes over.
//!
//! A directory that handed every requester the same one-time identifiers
//! would let the first peer to send consume the prekey while every other peer
//! holding that bundle failed with `UnknownPrekeyId` -- and a key that is
//! supposed to be used once would be shared among everyone who fetched in
//! that window. Dispensing is what rules that out.

use futures_util::FutureExt;
use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::DirConnection;

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

async fn start() -> std::net::SocketAddr {
    let server = Server::bind(&Config {
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
    let dir_addr = server.directory_addr().unwrap();
    tokio::spawn(server.serve());
    dir_addr
}

fn found_bundle(response: &DirResponse) -> &[u8] {
    match response {
        DirResponse::Found { bundle, .. } => bundle,
        other => panic!("expected Found, got {other:?}"),
    }
}

#[tokio::test]
async fn one_time_bundles_are_dispensed_once_each_then_the_pool_falls_back() {
    let dir_addr = start().await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let bob_r = DeviceAddr::new("+bob", 1);
    let identity = CryptoProvider::identity_key(&bob);
    let multi_use = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();

    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    assert_eq!(
        dir.register(&bob_r, identity.clone(), multi_use.clone(), |ch| {
            bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap(),
        DirResponse::Registered
    );

    // Distinguishable stand-ins for one-time bundles. The directory never
    // parses what it stores -- that is the point of pooling whole bundles --
    // so the dispensing property can be checked without involving a provider
    // at all.
    let pool: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0xAA, i]).collect();
    assert_eq!(
        dir.deposit_prekeys(&bob_r, identity.clone(), pool.clone(), |ch| {
            bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap(),
        DirResponse::Deposited(3)
    );

    // Three lookups, three different bundles.
    let mut served = Vec::new();
    for _ in 0..3 {
        let response = dir.lookup(&bob_r).await.unwrap();
        served.push(found_bundle(&response).to_vec());
    }
    let mut distinct = served.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        3,
        "a one-time bundle was served to two peers"
    );
    assert!(
        distinct.iter().all(|b| pool.contains(b)),
        "something other than the deposited pool was served"
    );

    // Exhaustion is a fallback, not a failure.
    for _ in 0..2 {
        let response = dir.lookup(&bob_r).await.unwrap();
        assert_eq!(
            found_bundle(&response),
            &multi_use[..],
            "an exhausted pool must fall back to the multi-use bundle"
        );
    }
}

#[tokio::test]
async fn only_the_registered_device_may_stock_its_pool() {
    let dir_addr = start().await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let bob_r = DeviceAddr::new("+bob", 1);
    let bob_identity = CryptoProvider::identity_key(&bob);
    let multi_use = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();

    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    dir.register(&bob_r, bob_identity.clone(), multi_use.clone(), |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // Mallory proves possession of *her* key, which is not the one bound to
    // Bob's address. Without this check she could stock Bob's pool with
    // bundles whose one-time private halves she holds.
    assert_eq!(
        dir.deposit_prekeys(
            &bob_r,
            CryptoProvider::identity_key(&mallory),
            vec![vec![0xEE]],
            |ch| mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap(),
        DirResponse::DepositRejected
    );

    // Bob's own lookups are unaffected: nothing was stocked.
    let response = dir.lookup(&bob_r).await.unwrap();
    assert_eq!(found_bundle(&response), &multi_use[..]);
}

#[tokio::test]
async fn a_forged_possession_signature_cannot_stock_a_pool() {
    let dir_addr = start().await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let bob_r = DeviceAddr::new("+bob", 1);
    let identity = CryptoProvider::identity_key(&bob);
    let multi_use = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();

    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    dir.register(&bob_r, identity.clone(), multi_use, |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // Bob's real identity, a signature that is not over the challenge.
    assert_eq!(
        dir.deposit_prekeys(&bob_r, identity, vec![vec![0xEE]], |_| vec![0u8; 64])
            .await
            .unwrap(),
        DirResponse::PossessionFailed
    );
}

#[tokio::test]
async fn registering_again_clears_a_stale_pool() {
    let dir_addr = start().await;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let bob_r = DeviceAddr::new("+bob", 1);
    let identity = CryptoProvider::identity_key(&bob);
    let first = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();

    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    dir.register(&bob_r, identity.clone(), first, |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    dir.deposit_prekeys(&bob_r, identity.clone(), vec![vec![0xAA]], |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // A new bundle carries a new signed prekey, so the pooled bundle built
    // against the old one must not be served afterwards.
    let second = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
    assert_eq!(
        dir.register(&bob_r, identity, second.clone(), |ch| {
            bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap(),
        DirResponse::Refreshed
    );

    let response = dir.lookup(&bob_r).await.unwrap();
    assert_eq!(
        found_bundle(&response),
        &second[..],
        "a bundle pooled against the superseded signed prekey was served"
    );
}
