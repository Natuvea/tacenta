//! A periodic snapshot writes the data directory while the server is still
//! running — not only on shutdown — so a crash loses at most one interval.

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::{DirResponse, Directory};
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::DirConnection;

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!("tacenta-periodic-{}", u64::from_le_bytes(b)))
}

#[tokio::test]
async fn a_periodic_snapshot_is_written_while_serving() {
    let data_dir = scratch_dir();
    let config = Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: Some(data_dir.clone()),
        tls: None,
        snapshot_interval: Some(Duration::from_millis(50)),
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };

    let server = Server::bind(&config).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    // Serve with a shutdown that never fires — we never stop it, so any
    // snapshot on disk came from the periodic tick, not a shutdown save.
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    // Register a client over the socket.
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);
    let alice_identity = CryptoProvider::identity_key(&alice);
    let bundle = now(CryptoProvider::publish_bundle(&mut alice, &mut rng)).unwrap();
    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    assert_eq!(
        dir.register(&alice_r, alice_identity.clone(), bundle.clone(), |ch| {
            alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap(),
        DirResponse::Registered
    );

    // Wait past a few intervals, then read the on-disk snapshot *without*
    // stopping the server: the registration must already be there.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let bytes = std::fs::read(data_dir.join("directory.snapshot"))
        .expect("periodic snapshot file should exist");
    let restored = Directory::restore(&bytes).expect("snapshot restores");
    assert_eq!(
        restored.identity(&alice_r),
        Some(&alice_identity[..]),
        "the periodic snapshot should contain the registration"
    );

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
    std::fs::remove_dir_all(&data_dir).ok();
}
