//! A registration made against a running server survives a restart: the
//! server persists on shutdown and loads on bind, so a client need not
//! re-register and the relay still recognises its identity.

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::{Connection, DirConnection};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// A unique temp directory for one test run.
fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!("tacenta-persist-{}", u64::from_le_bytes(b)))
}

#[tokio::test]
async fn registrations_survive_a_restart() {
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
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };

    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);
    let alice_identity = CryptoProvider::identity_key(&alice);

    // First run: register Alice over the directory socket, then shut the
    // server down (which persists to the data directory).
    {
        let server = Server::bind(&config).await.unwrap();
        let dir_addr = server.directory_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let bundle = now(CryptoProvider::publish_bundle(&mut alice, &mut rng)).unwrap();
        let mut dir = DirConnection::connect(dir_addr).await.unwrap();
        let outcome = dir
            .register(&alice_r, alice_identity.clone(), bundle.clone(), |ch| {
                alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
            })
            .await
            .unwrap();
        assert_eq!(outcome, DirResponse::Registered);
        drop(dir);

        stop.send(()).unwrap();
        handle
            .await
            .unwrap()
            .expect("first server persists cleanly");
    }

    // Second run: bind from the same data directory. The registration is
    // loaded, so Alice authenticates to the new relay *without* registering
    // again, and a lookup returns her bundle.
    {
        let server = Server::bind(&config).await.unwrap();
        let dir_addr = server.directory_addr().unwrap();
        let relay_addr = server.relay_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        // The loaded directory recognises Alice's identity at the relay.
        let conn = Connection::connect_as(relay_addr, &alice_r, |ch| {
            alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await;
        assert!(conn.is_ok(), "loaded directory should authenticate Alice");

        // And her bundle is still there to look up.
        let mut dir = DirConnection::connect(dir_addr).await.unwrap();
        let DirResponse::Found { identity, .. } = dir.lookup(&alice_r).await.unwrap() else {
            panic!("Alice's registration should have survived the restart");
        };
        assert_eq!(identity, alice_identity);

        stop.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    std::fs::remove_dir_all(&data_dir).ok();
}

/// The snapshot goes through a temp file and a rename, not a direct write.
///
/// **How this discriminates, since the obvious version of it does not.**
/// Asserting that no `.tmp` file is left over passes whether the code renames
/// or writes in place, so it guards nothing. Instead this plants a `.tmp` file
/// first: `write_atomically` creates that exact path, truncates it, and renames
/// it onto the target, so a correct persist *consumes* the planted file. A
/// regression to `fs::write` would leave it sitting there untouched.
///
/// The test is therefore coupled to `write_atomically`'s `<path>.tmp` naming.
/// That is the price of testing the mechanism rather than a side effect of it,
/// and it fails loudly rather than silently if the convention changes.
#[tokio::test]
async fn a_snapshot_leaves_no_partial_file_behind() {
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
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };

    let server = Server::bind(&config).await.unwrap();

    // Plant the temp file an atomic write must claim. Junk contents, so that if
    // it somehow ended up as the snapshot the load below would reject it.
    let planted = data_dir.join("relay.snapshot.tmp");
    std::fs::write(&planted, b"not a snapshot").unwrap();

    server.persist().unwrap();

    assert!(
        !planted.exists(),
        "the persist did not go through {}, so it was not an atomic write",
        planted.display()
    );
    assert!(
        data_dir.join("relay.snapshot").exists(),
        "expected the relay snapshot to exist"
    );
    // And what landed is a real snapshot, not the junk.
    drop(server);
    Server::bind(&config)
        .await
        .expect("the snapshot written over the planted temp file must load");

    std::fs::remove_dir_all(&data_dir).ok();
}

/// A torn snapshot stops the server starting — which is why the write must be
/// atomic.
///
/// `load` treats a corrupt snapshot as fatal rather than discarding it, so the
/// cost of a torn write is not lost state but a server that will not boot until
/// someone deletes the file by hand. This test plants the damage that a
/// non-atomic write could produce and pins that consequence, so the reason
/// `persist_state` uses `write_atomically` cannot be optimised away as tidiness.
#[tokio::test]
async fn a_truncated_snapshot_stops_the_server_starting() {
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
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };

    // A clean snapshot first, so the file we damage is a real one.
    let server = Server::bind(&config).await.unwrap();
    server.persist().unwrap();
    drop(server);

    let relay_snapshot = data_dir.join("relay.snapshot");
    let good = std::fs::read(&relay_snapshot).unwrap();
    assert!(
        good.len() > 1,
        "need a snapshot long enough to truncate meaningfully"
    );
    std::fs::write(&relay_snapshot, &good[..good.len() - 1]).unwrap();

    let Err(err) = Server::bind(&config).await else {
        panic!("a truncated snapshot must not be accepted");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    std::fs::remove_dir_all(&data_dir).ok();
}
