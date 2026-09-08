//! Full-stack integration: a real E2EE conversation routed through a
//! cryptographically blind relay.
//!
//! Alice and Bob exchange encrypted messages that travel as tacenta wire
//! envelopes through a `tacenta_relay::Relay` — the server component,
//! which holds a proven per-device delivery `Session` for each device
//! and *cannot* read the ciphertext it routes (it has no crypto
//! dependency; decision record 0012). This ties every layer together:
//! `tacenta-core::crypto` (open-tacenta), `tacenta-wire` (the proven
//! codec), `tacenta-state`/`tacenta-relay` (the proven per-device
//! delivery machine). The wire and delivery behavior is proven; the
//! cryptography is open-tacenta's (tested, not proven — `docs/claims.md`).

use futures_util::FutureExt;
use rand::{CryptoRng, Rng, TryRngCore};
use tacenta_core::crypto::{Address, CryptoProvider, DefaultProvider};
use tacenta_relay::{DeviceAddr, Relay, Request, Response, decode_response, encode_request};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// Sender seals a plaintext for `peer` and hands the relay the on-wire
/// bytes to route — encrypted, framed in an envelope, serialized by the
/// proven codec. The relay is given the recipient explicitly (transport
/// routing metadata) and never sees inside the payload.
fn send_via_relay<R: Rng + CryptoRng>(
    relay: &mut Relay,
    sender: &mut DefaultProvider,
    self_route: &DeviceAddr,
    peer_crypto: &Address,
    peer_route: &DeviceAddr,
    plaintext: &[u8],
    rng: &mut R,
) {
    let framed = now(CryptoProvider::encrypt(sender, peer_crypto, plaintext, rng)).unwrap();
    // The client sends a Send request over the byte protocol; the relay
    // handles it and replies Ok. (A socket transport would carry exactly
    // these request/response bytes.)
    let request = encode_request(&Request::Send {
        to: peer_route.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: framed,
        },
    });
    let response = relay
        .handle_bytes(self_route, &request)
        .expect("relay handles request");
    assert_eq!(decode_response(&response), Some(Response::Ok));
}

/// Recipient drains its relay queue: decrypt every pending envelope from
/// `peer`, then acknowledge, advancing the proven delivery cursor.
fn drain_from_relay<R: Rng + CryptoRng>(
    relay: &mut Relay,
    recipient: &mut DefaultProvider,
    peer_crypto: &Address,
    self_route: &DeviceAddr,
    rng: &mut R,
) -> Vec<Vec<u8>> {
    let poll = encode_request(&Request::Poll {
        device: self_route.clone(),
    });
    let Some(Response::Delivered { from, messages }) = decode_response(
        &relay
            .handle_bytes(self_route, &poll)
            .expect("relay handles poll"),
    ) else {
        panic!("expected Delivered");
    };
    let mut out = Vec::new();
    for message in &messages {
        out.push(
            now(CryptoProvider::decrypt(
                recipient,
                peer_crypto,
                &message.envelope.payload,
                rng,
            ))
            .unwrap(),
        );
    }
    if !messages.is_empty() {
        let ack = encode_request(&Request::Ack {
            device: self_route.clone(),
            up_to: from + messages.len() as u64,
        });
        assert_eq!(
            decode_response(
                &relay
                    .handle_bytes(self_route, &ack)
                    .expect("relay handles ack")
            ),
            Some(Response::Acked { accepted: true })
        );
    }
    out
}

#[test]
fn e2ee_conversation_through_a_blind_relay() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut relay = Relay::new();

    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    // The trait method, so the test names the seam's `Address` and not a
    // provider type.
    let alice_c = CryptoProvider::address(&alice);
    let bob_c = CryptoProvider::address(&bob);
    // The relay's routing addresses (its own key type — no crypto here).
    let alice_r = DeviceAddr::new("+alice", 1);
    let bob_r = DeviceAddr::new("+bob", 1);

    let bob_bundle = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
    now(CryptoProvider::establish_session(
        &mut alice,
        &bob_c,
        &bob_bundle,
        &mut rng,
    ))
    .unwrap();

    // Alice → Bob, twice (a PreKey message then a ratchet message).
    send_via_relay(
        &mut relay,
        &mut alice,
        &alice_r,
        &bob_c,
        &bob_r,
        b"meet at the docks",
        &mut rng,
    );
    send_via_relay(
        &mut relay,
        &mut alice,
        &alice_r,
        &bob_c,
        &bob_r,
        b"bring the manifest",
        &mut rng,
    );

    assert_eq!(relay.pending(&bob_r).len(), 2);
    let got = drain_from_relay(&mut relay, &mut bob, &alice_c, &bob_r, &mut rng);
    assert_eq!(
        got,
        vec![
            b"meet at the docks".to_vec(),
            b"bring the manifest".to_vec()
        ]
    );
    assert_eq!(relay.cursor(&bob_r), 2);
    assert!(relay.pending(&bob_r).is_empty());

    // Bob → Alice (a ratchet-message reply, routed back through the relay).
    send_via_relay(
        &mut relay,
        &mut bob,
        &bob_r,
        &alice_c,
        &alice_r,
        b"on my way",
        &mut rng,
    );
    let reply = drain_from_relay(&mut relay, &mut alice, &bob_c, &alice_r, &mut rng);
    assert_eq!(reply, vec![b"on my way".to_vec()]);
    assert_eq!(relay.cursor(&alice_r), 1);
}
