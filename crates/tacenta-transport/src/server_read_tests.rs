//! The relay server's loop reads a client's request frames and writes push
//! notifications on the same connection. A push that is written while a
//! request frame is half read must leave that frame intact.
//!
//! The client is scripted over an in-memory pipe and the tests run on a
//! single-threaded runtime, so where the server has got to when a push is
//! injected is known: `settle` lets it run until it is waiting for more bytes.

use super::*;
use tacenta_relay::{StoredMessage, decode_response, encode_request};
use tacenta_wire::{Envelope, Kind};
use tokio::io::DuplexStream;

struct NameAuth;
impl Authenticator for NameAuth {
    fn challenge(&self) -> Vec<u8> {
        b"fixed-test-challenge".to_vec()
    }
    fn verify(&self, device: &DeviceAddr, _challenge: &[u8], signature: &[u8]) -> bool {
        signature == device.user.as_bytes()
    }
}

struct Scripted {
    client: DuplexStream,
    push: mpsc::UnboundedSender<()>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Run the server's post-handshake loop for `+alice` over a pipe, with a push
/// channel the test holds the sender of.
fn serve_alice() -> Scripted {
    let (client, mut server_end) = tokio::io::duplex(1 << 16);
    let (push, mut push_rx) = mpsc::unbounded_channel::<()>();
    let relay = server(Relay::new(), NameAuth);
    let alice = DeviceAddr::new("+alice", 1);
    let served = tokio::spawn(async move {
        serve_authenticated(&mut server_end, &relay, &alice, &mut push_rx).await
    });
    Scripted {
        client,
        push,
        served,
    }
}

fn alice() -> DeviceAddr {
    DeviceAddr::new("+alice", 1)
}

fn send(byte: u8, len: usize) -> Vec<u8> {
    encode_request(&Request::Send {
        to: alice(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: vec![byte; len],
        },
    })
}

fn poll() -> Vec<u8> {
    encode_request(&Request::Poll { device: alice() })
}

/// A frame as it goes on the wire: length prefix, then the bytes.
fn wire(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Let the server task run until it is waiting for something.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

async fn next_frame(client: &mut DuplexStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), read_frame(client))
        .await
        .expect("the server sent nothing")
        .expect("the pipe failed")
        .expect("the server closed the connection")
}

async fn expect_push(client: &mut DuplexStream) {
    assert_eq!(next_frame(client).await, [TAG_PUSH]);
}

async fn expect_response(client: &mut DuplexStream) -> Response {
    let frame = next_frame(client).await;
    assert_eq!(frame[0], TAG_RESPONSE, "expected a response frame");
    decode_response(&frame[1..]).expect("the response decodes")
}

/// A push lands after each possible number of bytes of a request frame has
/// been written, including inside the length prefix. Each frame is still
/// served, on the one connection, which stays open.
#[tokio::test]
async fn a_push_at_any_point_in_a_request_frame_leaves_the_frame_intact() {
    let mut s = serve_alice();
    let frame = wire(&poll());
    for cut in 1..frame.len() {
        s.client.write_all(&frame[..cut]).await.unwrap();
        settle().await;
        s.push.send(()).unwrap();
        expect_push(&mut s.client).await;
        s.client.write_all(&frame[cut..]).await.unwrap();
        assert_eq!(
            expect_response(&mut s.client).await,
            Response::Delivered {
                from: 0,
                messages: vec![]
            },
            "the request cut after {cut} bytes"
        );
    }
    drop(s.client);
    s.served
        .await
        .unwrap()
        .expect("the connection ended cleanly");
}

/// A push after every byte of a frame written one byte at a time, except the
/// last: the frame is then complete, and the response is what comes back.
#[tokio::test]
async fn a_push_after_every_byte_of_a_request_frame_leaves_the_frame_intact() {
    let mut s = serve_alice();
    let frame = wire(&send(9, 40));
    let (last, inside) = frame.split_last().unwrap();
    for byte in inside {
        s.client.write_all(&[*byte]).await.unwrap();
        settle().await;
        s.push.send(()).unwrap();
        expect_push(&mut s.client).await;
    }
    s.client.write_all(&[*last]).await.unwrap();
    assert_eq!(expect_response(&mut s.client).await, Response::Ok);
    s.client.write_all(&wire(&poll())).await.unwrap();
    let Response::Delivered { messages, .. } = expect_response(&mut s.client).await else {
        panic!("expected the mail");
    };
    assert_eq!(
        messages,
        vec![StoredMessage {
            from: alice(),
            envelope: Envelope {
                kind: Kind::Dm,
                payload: vec![9; 40]
            }
        }]
    );
}

/// Several frames in order across pushes: a large frame split in two with a
/// push between, then a small one, then a poll. Each is answered, in order.
#[tokio::test]
async fn frames_are_served_in_order_across_a_push_in_the_middle_of_one() {
    let mut s = serve_alice();
    let big = wire(&send(1, 30_000));
    let cut = big.len() / 2;
    s.client.write_all(&big[..cut]).await.unwrap();
    settle().await;
    s.push.send(()).unwrap();
    expect_push(&mut s.client).await;
    s.client.write_all(&big[cut..]).await.unwrap();
    s.client.write_all(&wire(&send(2, 3))).await.unwrap();
    s.client.write_all(&wire(&poll())).await.unwrap();

    assert_eq!(expect_response(&mut s.client).await, Response::Ok);
    assert_eq!(expect_response(&mut s.client).await, Response::Ok);
    let Response::Delivered { from, messages } = expect_response(&mut s.client).await else {
        panic!("expected the mail");
    };
    assert_eq!(from, 0);
    let payloads: Vec<_> = messages
        .iter()
        .map(|m| m.envelope.payload.clone())
        .collect();
    assert_eq!(payloads, vec![vec![1u8; 30_000], vec![2u8; 3]]);
}

/// A `FrameReader` dropped part-way through a frame, at every chunk of it,
/// gives the frame whole on a later call, and the next frame after it.
#[tokio::test]
async fn a_frame_reader_dropped_mid_frame_carries_on_with_the_same_frame() {
    let (mut server_end, mut client) = tokio::io::duplex(1 << 16);
    let mut reader = FrameReader::new();
    for body in [
        (0..1_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        Vec::new(),
        b"after".to_vec(),
    ] {
        let mut got = None;
        for chunk in wire(&body).chunks(7) {
            client.write_all(chunk).await.unwrap();
            // One poll of the read, then it is dropped unless it finished.
            if let Ok(result) =
                tokio::time::timeout(Duration::ZERO, reader.next(&mut server_end)).await
            {
                got = Some(result.unwrap().unwrap());
                break;
            }
        }
        assert_eq!(got.expect("the frame was completed"), body);
    }
}
