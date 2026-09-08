//! The relay and directory protocols run unchanged over TLS: a client
//! pinning the server's self-signed certificate connects, and a client
//! trusting the wrong certificate is refused at the handshake.

use std::sync::{Arc, Mutex};

use tacenta_directory::{DirResponse, Directory};
use tacenta_relay::{
    DeviceAddr, Relay, Request, Response, StoredMessage, decode_response, encode_request,
};
use tacenta_transport::{
    Authenticator, ClientTls, Connection, DirConnection, Possession, ServerTls, dir_server,
    serve_directory_tls, serve_tls, server,
};
use tacenta_wire::{Envelope, Kind};
use tokio::net::TcpListener;

/// A trivial authenticator for transport tests: the "signature" is the
/// device name. No real crypto — this exercises the TLS wrapping and the
/// framed protocol, not the identity crypto (covered in `tacenta-core`).
struct NameAuth;
impl Authenticator for NameAuth {
    fn challenge(&self) -> Vec<u8> {
        b"fixed-test-challenge".to_vec()
    }
    fn verify(&self, device: &DeviceAddr, _challenge: &[u8], signature: &[u8]) -> bool {
        signature == device.user.as_bytes()
    }
}

/// A trivial possession verifier: the "signature" is the submitted identity.
struct NamePossession;
impl Possession for NamePossession {
    fn challenge(&self) -> Vec<u8> {
        b"fixed-test-challenge".to_vec()
    }
    fn verify(&self, identity: &[u8], _challenge: &[u8], signature: &[u8]) -> bool {
        signature == identity
    }
}

/// A fresh self-signed certificate for `localhost`: (cert DER, PKCS#8 key DER).
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (key.cert.der().to_vec(), key.key_pair.serialize_der())
}

#[tokio::test]
async fn relay_protocol_runs_over_tls() {
    let (cert, key) = self_signed();
    let server_tls = ServerTls::from_der(vec![cert.clone()], key).unwrap();
    let client_tls = ClientTls::trusting(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_tls(
        listener,
        server(Relay::new(), NameAuth),
        server_tls,
    ));

    let bob = DeviceAddr::new("+bob", 1);
    let mut conn =
        Connection::connect_as_tls(addr, "localhost", &client_tls, &bob, |_| b"+bob".to_vec())
            .await
            .unwrap();

    let envelope = Envelope {
        kind: Kind::Dm,
        payload: vec![0xaa, 0xbb],
    };
    let resp = conn
        .request(&encode_request(&Request::Send {
            to: bob.clone(),
            envelope: envelope.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(decode_response(&resp), Some(Response::Ok));

    let resp = conn
        .request(&encode_request(&Request::Poll {
            device: bob.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(
        decode_response(&resp),
        Some(Response::Delivered {
            from: 0,
            messages: vec![StoredMessage {
                from: bob,
                envelope
            }],
        })
    );
}

#[tokio::test]
async fn directory_protocol_runs_over_tls() {
    let (cert, key) = self_signed();
    let server_tls = ServerTls::from_der(vec![cert.clone()], key).unwrap();
    let client_tls = ClientTls::trusting(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_directory_tls(
        listener,
        dir_server(Arc::new(Mutex::new(Directory::new())), NamePossession),
        server_tls,
    ));

    let bob = DeviceAddr::new("+bob", 1);
    let mut dir = DirConnection::connect_tls(addr, "localhost", &client_tls)
        .await
        .unwrap();
    let outcome = dir
        .register(&bob, b"bob-id".to_vec(), b"bob-bundle".to_vec(), |_ch| {
            b"bob-id".to_vec()
        })
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);

    let DirResponse::Found { bundle, .. } = dir.lookup(&bob).await.unwrap() else {
        panic!("expected Bob's material");
    };
    assert_eq!(bundle, b"bob-bundle");
}

#[tokio::test]
async fn a_client_trusting_the_wrong_certificate_is_refused() {
    let (server_cert, server_key) = self_signed();
    let (other_cert, _) = self_signed();
    let server_tls = ServerTls::from_der(vec![server_cert], server_key).unwrap();
    // The client trusts a *different* certificate than the server presents.
    let client_tls = ClientTls::trusting(other_cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_tls(
        listener,
        server(Relay::new(), NameAuth),
        server_tls,
    ));

    let bob = DeviceAddr::new("+bob", 1);
    let result =
        Connection::connect_as_tls(addr, "localhost", &client_tls, &bob, |_| b"+bob".to_vec())
            .await;
    assert!(
        result.is_err(),
        "TLS handshake must reject an untrusted cert"
    );
}
