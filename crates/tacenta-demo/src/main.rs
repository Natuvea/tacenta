//! A runnable demonstration of the whole Tacenta stack.
//!
//! Starts a real [`tacenta_server::Server`] — the directory service and
//! the relay server over one shared directory — then acts as two clients:
//! they register their identity keys and prekey bundles over the directory
//! socket, authenticate to the relay, look each other up, and drive an
//! end-to-end encrypted conversation, narrating each step and the trust
//! property it exercises. Run with `cargo run -p tacenta-demo`.
//!
//! Nothing here is new machinery; it points the client crates at the same
//! server a real deployment runs (`cargo run -p tacenta-server`).

use futures_util::FutureExt;
use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::{DeviceAddr, Request, Response, decode_response, encode_request};
use tacenta_server::{Config, Server};
use tacenta_transport::{Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// Publish a party's identity key and prekey bundle to the directory
/// service over the socket, proving possession of the identity key.
async fn register_with_directory(
    dir_addr: SocketAddr,
    route: &DeviceAddr,
    party: &mut DefaultProvider,
) -> std::io::Result<()> {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    let identity = CryptoProvider::identity_key(party);
    let bundle_bytes = bundle.clone();
    let mut conn = DirConnection::connect(dir_addr).await?;
    let outcome = conn
        .register(route, identity, bundle_bytes, |ch| {
            party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await?;
    assert_eq!(outcome, DirResponse::Registered);
    Ok(())
}

#[tokio::main]
async fn main() {
    run().await.expect("demo run");
}

async fn run() -> std::io::Result<()> {
    let mut rng = rand::rngs::OsRng.unwrap_err();

    // Two participants generate identities.
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    // The trait method, so the demo names the seam's `Address` and not a
    // provider type.
    let alice_c = CryptoProvider::address(&alice);
    let bob_c = CryptoProvider::address(&bob);
    let alice_r = DeviceAddr::new("+alice", 1);
    let bob_r = DeviceAddr::new("+bob", 1);
    println!("· generated identities for +alice and +bob");

    // Start a real server — the directory service and the relay server
    // over one shared directory — on ephemeral ports, and serve it in the
    // background. This is the same server a deployment runs.
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
    .await?;
    let dir_addr = server.directory_addr()?;
    let relay_addr = server.relay_addr()?;
    tokio::spawn(server.serve());
    println!("· directory service listening on {dir_addr} (it stores only public keys)");
    println!("· relay server listening on {relay_addr} (it can never read message contents)");

    // Each party registers over the directory socket, proving possession
    // of its identity key. Nothing is exchanged out of band.
    register_with_directory(dir_addr, &alice_r, &mut alice).await?;
    register_with_directory(dir_addr, &bob_r, &mut bob).await?;
    println!(
        "· +alice and +bob registered with the directory\n  (proof of possession, trust on first use)"
    );

    // Both clients connect to the relay and authenticate by signing the
    // challenge; the relay verifies each against the identity the shared
    // directory now holds.
    let mut alice_conn = Connection::connect_as(relay_addr, &alice_r, |ch| {
        alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await?;
    let mut bob_conn = Connection::connect_as(relay_addr, &bob_r, |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await?;
    println!("· +alice and +bob authenticated to the relay with their identity keys");

    // Alice *looks up* Bob over the directory socket and opens a session.
    let mut alice_dir = DirConnection::connect(dir_addr).await?;
    let DirResponse::Found { bundle, .. } = alice_dir.lookup(&bob_r).await? else {
        panic!("bob is registered");
    };
    // The trait takes the published bytes directly, so the demo never
    // deserializes a bundle just to hand it straight back.
    now(CryptoProvider::establish_session(
        &mut alice, &bob_c, &bundle, &mut rng,
    ))
    .unwrap();
    println!(
        "· +alice looked +bob up in the directory and opened an encrypted session\n  (X3DH/PQXDH, Kyber1024)\n"
    );

    // A short conversation, each message end-to-end encrypted.
    say(
        &mut alice_conn,
        &mut alice,
        &bob_c,
        &bob_r,
        "meet at the north dock at dawn",
        &mut rng,
    )
    .await?;
    hear(&mut bob_conn, &mut bob, &alice_c, &bob_r, &mut rng).await?;

    say(
        &mut bob_conn,
        &mut bob,
        &alice_c,
        &alice_r,
        "understood — bringing the charts",
        &mut rng,
    )
    .await?;
    hear(&mut alice_conn, &mut alice, &bob_c, &alice_r, &mut rng).await?;

    say(
        &mut alice_conn,
        &mut alice,
        &bob_c,
        &bob_r,
        "good. tell no one",
        &mut rng,
    )
    .await?;
    hear(&mut bob_conn, &mut bob, &alice_c, &bob_r, &mut rng).await?;

    println!("\n· conversation complete — every message was encrypted end to end,");
    println!("  routed by a server that only ever saw opaque bytes.");
    Ok(())
}

/// Encrypt `text` and send it to `to_route` over the sender's socket.
/// Prints what goes on the wire (ciphertext), showing the server sees no
/// plaintext.
async fn say(
    conn: &mut Connection,
    sender: &mut DefaultProvider,
    peer_c: &tacenta_core::crypto::Address,
    to_route: &DeviceAddr,
    text: &str,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
) -> std::io::Result<()> {
    let framed = now(CryptoProvider::encrypt(
        sender,
        peer_c,
        text.as_bytes(),
        rng,
    ))
    .unwrap();
    let on_wire = framed.len();
    let request = encode_request(&Request::Send {
        to: to_route.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: framed,
        },
    });
    let resp = conn.request(&request).await?;
    assert_eq!(decode_response(&resp), Some(Response::Ok));
    let who = CryptoProvider::address(sender).user;
    println!("  {who} → sends {on_wire} bytes of ciphertext: \"{text}\"");
    Ok(())
}

/// Wait to be *pushed* a notification, then poll `self_route`'s queue,
/// decrypt every pending message, and acknowledge. The push is what makes
/// this immediate — no blind polling.
async fn hear(
    conn: &mut Connection,
    recipient: &mut DefaultProvider,
    peer_c: &tacenta_core::crypto::Address,
    self_route: &DeviceAddr,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
) -> std::io::Result<()> {
    conn.next_notification().await.expect("server push");
    println!("  {} ← notified of new mail by the server", self_route.user);
    let poll = encode_request(&Request::Poll {
        device: self_route.clone(),
    });
    let Some(Response::Delivered { from, messages }) = decode_response(&conn.request(&poll).await?)
    else {
        panic!("expected Delivered");
    };
    let who = CryptoProvider::address(recipient).user;
    for message in &messages {
        // The relay tells the recipient who each message is from.
        let text = now(CryptoProvider::decrypt(
            recipient,
            peer_c,
            &message.envelope.payload,
            rng,
        ))
        .unwrap();
        println!(
            "  {who} ← decrypts (from {}): \"{}\"",
            message.from.user,
            String::from_utf8_lossy(&text)
        );
    }
    if !messages.is_empty() {
        let ack = encode_request(&Request::Ack {
            device: self_route.clone(),
            up_to: from + messages.len() as u64,
        });
        assert_eq!(
            decode_response(&conn.request(&ack).await?),
            Some(Response::Acked { accepted: true })
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The demo runs to completion — a smoke test that the wiring stays
    /// intact.
    #[tokio::test]
    async fn demo_runs() {
        super::run().await.unwrap();
    }
}
