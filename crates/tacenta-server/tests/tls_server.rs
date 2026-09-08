//! The packaged server serves the whole flow over TLS: a client pinning
//! the server's certificate registers over the directory, authenticates to
//! the relay, and routes a message — all inside the encrypted transport,
//! with the real identity crypto underneath.

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::{
    DeviceAddr, Request, Response, StoredMessage, decode_response, encode_request,
};
use tacenta_server::{Config, Server, TlsFiles};
use tacenta_transport::{ClientTls, Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// Write a self-signed cert + key to temp PEM files. Returns their paths
/// and the certificate DER (for the client to pin).
fn write_self_signed() -> (PathBuf, PathBuf, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    let base = std::env::temp_dir().join(format!("tacenta-tls-{}", u64::from_le_bytes(b)));
    std::fs::create_dir_all(&base).unwrap();
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    std::fs::write(&cert_path, key.cert.pem()).unwrap();
    std::fs::write(&key_path, key.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path, key.cert.der().to_vec())
}

#[tokio::test]
async fn server_serves_the_whole_flow_over_tls() {
    let (cert_path, key_path, cert_der) = write_self_signed();
    let config = Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: None,
        tls: Some(TlsFiles {
            cert_pem: cert_path.clone(),
            key_pem: key_path.clone(),
        }),
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };
    let server = Server::bind(&config).await.unwrap();
    assert!(server.is_tls());
    let dir_addr = server.directory_addr().unwrap();
    let relay_addr = server.relay_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    let client_tls = ClientTls::trusting(cert_der).unwrap();
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);

    // Register over the TLS directory connection.
    let bundle = now(CryptoProvider::publish_bundle(&mut alice, &mut rng)).unwrap();
    let mut dir = DirConnection::connect_tls(dir_addr, "localhost", &client_tls)
        .await
        .unwrap();
    let outcome = dir
        .register(
            &alice_r,
            CryptoProvider::identity_key(&alice),
            bundle.clone(),
            |ch| alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);

    // Authenticate to the TLS relay against that registration and route a
    // message to self.
    let mut conn =
        Connection::connect_as_tls(relay_addr, "localhost", &client_tls, &alice_r, |ch| {
            alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();

    let envelope = Envelope {
        kind: Kind::Dm,
        payload: b"encrypted under TLS, and end to end".to_vec(),
    };
    let resp = conn
        .request(&encode_request(&Request::Send {
            to: alice_r.clone(),
            envelope: envelope.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(decode_response(&resp), Some(Response::Ok));

    let resp = conn
        .request(&encode_request(&Request::Poll {
            device: alice_r.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(
        decode_response(&resp),
        Some(Response::Delivered {
            from: 0,
            messages: vec![StoredMessage {
                from: alice_r.clone(),
                envelope
            }],
        })
    );

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
    std::fs::remove_dir_all(cert_path.parent().unwrap()).ok();
}
