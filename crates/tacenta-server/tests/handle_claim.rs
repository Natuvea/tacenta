//! An unauthenticated caller cannot claim an account-shaped handle.
//!
//! `docs/threat-model.md` states "A client never chooses its own handle — the
//! server derives it". On the *provisioning* path the handle comes from a
//! validated session token. The directory service takes `DeviceAddr` from the
//! request, with proof of possession only of the key being submitted -- a key
//! the caller just generated -- so it must refuse the account namespace
//! itself: the unauthenticated `Register` path rejects any handle containing
//! `/`, the character `tacenta_accounts::handle` uses to build every account
//! handle, which makes the two namespaces disjoint by construction.
//!
//! The first two tests assert the refusal; the third pins the case that must
//! keep working, since provisioning binds `tenant/user` through a different
//! door.

use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::DirConnection;

fn config() -> Config {
    Config {
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
    }
}

/// An unauthenticated caller binds a handle it has no claim to.
///
/// Nothing here presents an account, a session token, or any credential beyond
/// a keypair generated on the spot.
#[tokio::test]
async fn an_account_shaped_handle_is_refused_over_the_public_path() {
    let server = Server::bind(&config()).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    let mut rng = rand::rngs::OsRng.unwrap_err();
    // The attacker generates a key and names a handle belonging to someone else.
    let mut attacker = DefaultProvider::generate("acme/alice", 1, &mut rng).unwrap();
    let victims_address = DeviceAddr::new("acme/alice", 1);
    let bundle = CryptoProvider::publish_bundle(&mut attacker, &mut rng)
        .await
        .unwrap();
    let attacker_identity = CryptoProvider::identity_key(&attacker);

    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    let outcome = dir
        .register(&victims_address, attacker_identity.clone(), bundle, |ch| {
            attacker.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();

    assert_eq!(
        outcome,
        DirResponse::ReservedHandle,
        "an account-shaped handle must not be bindable over the unauthenticated path"
    );

    // And nothing was bound, so a lookup finds no one to impersonate.
    assert_eq!(
        dir.lookup(&victims_address).await.unwrap(),
        DirResponse::NotFound,
        "the refused registration must not have bound anything"
    );
    let _ = attacker_identity;

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
}

/// And because nothing can be squatted, the owner is not locked out.
///
/// Were the attacker able to bind the handle first, trust-on-first-use would
/// refuse the rightful owner permanently, through provisioning too, since it
/// ends in the same `Directory::register`: the correct rule applied to a
/// binding that should never have existed would become the lock-out.
#[tokio::test]
async fn no_squatting_means_no_lock_out() {
    let server = Server::bind(&config()).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    let mut rng = rand::rngs::OsRng.unwrap_err();
    let address = DeviceAddr::new("acme/alice", 1);

    let mut attacker = DefaultProvider::generate("acme/alice", 1, &mut rng).unwrap();
    let attacker_bundle = CryptoProvider::publish_bundle(&mut attacker, &mut rng)
        .await
        .unwrap();
    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    dir.register(
        &address,
        CryptoProvider::identity_key(&attacker),
        attacker_bundle,
        |ch| attacker.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
    )
    .await
    .unwrap();

    // Alice now arrives with her own key -- through any path, including the
    // authenticated provisioning one, which ends in this same `register`.
    let mut alice = DefaultProvider::generate("acme/alice", 1, &mut rng).unwrap();
    let alice_bundle = CryptoProvider::publish_bundle(&mut alice, &mut rng)
        .await
        .unwrap();
    let outcome = dir
        .register(
            &address,
            CryptoProvider::identity_key(&alice),
            alice_bundle,
            |ch| alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();

    assert_eq!(
        outcome,
        DirResponse::ReservedHandle,
        "neither party binds it over this path, so there is no lock-out to inherit"
    );

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
}
