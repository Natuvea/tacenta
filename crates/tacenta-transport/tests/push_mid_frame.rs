//! A client writes one request frame in two parts, and a push notification for
//! it is written by the server between them. Over a real socket the frame is
//! served and the connection stays in step, the same as with no push.

use std::time::Duration;

use tacenta_relay::{
    DeviceAddr, Relay, Request, Response, decode_response, encode_auth, encode_request,
};
use tacenta_transport::{Authenticator, serve, server};
use tacenta_wire::{Envelope, Kind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TAG_RESPONSE: u8 = 0;
const TAG_PUSH: u8 = 1;

struct NameAuth;
impl Authenticator for NameAuth {
    fn challenge(&self) -> Vec<u8> {
        b"fixed-test-challenge".to_vec()
    }
    fn verify(&self, device: &DeviceAddr, _challenge: &[u8], signature: &[u8]) -> bool {
        signature == device.user.as_bytes()
    }
}

async fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

fn wire(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

async fn login(addr: std::net::SocketAddr, device: &DeviceAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    read_frame(&mut stream).await.unwrap();
    stream
        .write_all(&wire(&encode_auth(device, device.user.as_bytes())))
        .await
        .unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), [1]);
    stream
}

/// Alice writes half of a large `Send`; Bob then sends her a message, which
/// the server announces to her connection; she writes the rest of the `Send`
/// and a `Poll`. Both requests are answered, and her own `Send` and Bob's
/// are in the mail.
#[tokio::test]
async fn a_push_while_a_request_is_half_read_does_not_lose_the_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, server(Relay::new(), NameAuth)));
    let alice = DeviceAddr::new("+alice", 1);
    let bob = DeviceAddr::new("+bob", 1);
    let mut alice_stream = login(addr, &alice).await;
    let mut bob_stream = login(addr, &bob).await;

    let large = wire(&encode_request(&Request::Send {
        to: alice.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: vec![0x42; 100_000],
        },
    }));
    let cut = large.len() / 2;
    alice_stream.write_all(&large[..cut]).await.unwrap();
    // The server reads what has arrived and waits for the rest.
    tokio::time::sleep(Duration::from_millis(150)).await;

    bob_stream
        .write_all(&wire(&encode_request(&Request::Send {
            to: alice.clone(),
            envelope: Envelope {
                kind: Kind::Dm,
                payload: vec![1],
            },
        })))
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut bob_stream).await.unwrap()[0],
        TAG_RESPONSE,
        "Bob's send is answered"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;

    alice_stream.write_all(&large[cut..]).await.unwrap();
    alice_stream
        .write_all(&wire(&encode_request(&Request::Poll {
            device: alice.clone(),
        })))
        .await
        .unwrap();

    // Alice's stream carries pushes for the two sends to her and the two
    // responses; the order of a push relative to a response is not fixed.
    let mut tags = Vec::new();
    let mut responses = Vec::new();
    while responses.len() < 2 {
        let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_secs(10), read_frame(&mut alice_stream)).await
        else {
            panic!(
                "frames so far: {tags:?}; the connection stopped before both requests were answered"
            );
        };
        tags.push(frame[0]);
        if frame[0] == TAG_RESPONSE {
            responses.push(decode_response(&frame[1..]).unwrap());
        } else {
            assert_eq!(frame[0], TAG_PUSH);
        }
    }
    assert_eq!(responses[0], Response::Ok);
    let Response::Delivered { messages, .. } = &responses[1] else {
        panic!("the second response is the mail, got {:?}", responses[1]);
    };
    let payloads: Vec<_> = messages.iter().map(|m| m.envelope.payload.len()).collect();
    assert_eq!(payloads, [1, 100_000], "Bob's message, then Alice's own");
}
