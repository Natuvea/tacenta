//! What a `Connection` queues when the peer sends response frames that no
//! request is waiting for.
//!
//! The peer here is scripted: it completes the handshake and then writes what
//! the test says, so the number of frames the connection has taken from the
//! pipe is known exactly.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most unrequested response frames the connection is expected to queue.
const BOUND: usize = 2;

/// Bytes in each frame of the long run of frames. The pipe below holds a quarter of
/// one, so a frame is written completely only as the connection's reader takes
/// it: the count of finished writes is the count of frames read.
const LARGE_FRAME: usize = 256 * 1024;
const PIPE: usize = 64 * 1024;

async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("timed out")
}

/// A connection to a scripted peer that, once the handshake is done, writes
/// `frames` response frames of `size` payload bytes each without being asked,
/// then holds the pipe open and says nothing more. Each frame's payload is
/// its index. Returns the connection and the number of frames whose write has
/// finished.
async fn unrequested(frames: usize, size: usize) -> (Connection, Arc<AtomicUsize>) {
    let (client_end, server_end) = tokio::io::duplex(PIPE);
    let written = Arc::new(AtomicUsize::new(0));
    let counted = written.clone();
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(server_end);
        write_frame(&mut write, b"challenge").await.unwrap();
        read_frame(&mut read).await.unwrap();
        write_frame(&mut write, &[1]).await.unwrap();
        for index in 0..frames {
            let mut frame = vec![index as u8; 1 + size];
            frame[0] = TAG_RESPONSE;
            if write_frame(&mut write, &frame).await.is_err() {
                return;
            }
            counted.fetch_add(1, Ordering::SeqCst);
        }
        std::future::pending::<()>().await;
    });
    let bob = DeviceAddr::new("+bob", 1);
    let conn = Connection::establish(client_end, &bob, |_| b"+bob".to_vec())
        .await
        .unwrap();
    (conn, written)
}

/// Wait until the connection's reader has stopped, which it announces on the
/// connection's signal.
async fn reader_stopped(conn: &Connection) -> bool {
    tokio::time::timeout(Duration::from_secs(10), conn.signal().notified())
        .await
        .is_ok()
}

/// A peer that sends response frames nobody asked for does not get an
/// unbounded queue: the connection stops reading it after a handful of
/// frames, and the frames it never read stay in the pipe. Here it offers 64
/// frames of 256 KiB.
#[tokio::test]
async fn many_unrequested_responses_are_not_read_without_bound() {
    let (mut conn, written) = unrequested(64, LARGE_FRAME).await;
    assert!(
        reader_stopped(&conn).await,
        "the reader was still reading after {} unrequested frames",
        written.load(Ordering::SeqCst)
    );
    let taken = written.load(Ordering::SeqCst);
    assert!(
        taken <= BOUND + 2,
        "{taken} frames were read from the pipe before the reader stopped"
    );
    let err = conn
        .request(b"anything")
        .await
        .expect_err("a connection that overflowed refuses requests");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
}

/// The frame after the bound is the one that ends the connection: `BOUND`
/// unrequested frames are queued and delivered in order without a failure.
#[tokio::test]
async fn a_burst_up_to_the_bound_is_delivered_in_order() {
    let (mut conn, written) = unrequested(BOUND, 4).await;
    while written.load(Ordering::SeqCst) < BOUND {
        tokio::task::yield_now().await;
    }
    for index in 0..BOUND {
        let frame = within(conn.request(b"ask")).await.unwrap();
        assert_eq!(frame, vec![index as u8; 4]);
    }
}

/// One frame past the bound ends the connection and every later request
/// fails, rather than being answered from the queue.
#[tokio::test]
async fn one_frame_past_the_bound_ends_the_connection() {
    let (mut conn, _written) = unrequested(BOUND + 1, 4).await;
    assert!(reader_stopped(&conn).await, "the reader is still running");
    let err = within(conn.request(b"ask"))
        .await
        .expect_err("the queue is not served after it overflowed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    // And it stays failed: the queued frames are not served on a second try.
    let again = within(conn.request(b"ask")).await.unwrap_err();
    assert_eq!(again.kind(), std::io::ErrorKind::InvalidData, "{again}");
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// Poll `future` at most `polls` times: `None` if it has not finished by then,
/// having been dropped at a point the schedule chose.
async fn at_most<F: std::future::Future>(future: F, polls: u32) -> Option<F::Output> {
    use std::pin::Pin;
    use std::task::Poll;
    let mut future = Box::pin(future);
    let mut used = 0;
    std::future::poll_fn(move |cx| {
        if used >= polls {
            return Poll::Ready(None);
        }
        used += 1;
        match Pin::as_mut(&mut future).poll(cx) {
            Poll::Ready(value) => Poll::Ready(Some(value)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// A conforming relay: it answers every complete request frame once, in
/// order, after a scheduling delay of a few yields, echoing the request's
/// first eight bytes.
fn conforming_relay(pipe: usize, seed: u64) -> tokio::io::DuplexStream {
    let (client_end, server_end) = tokio::io::duplex(pipe);
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(server_end);
        write_frame(&mut write, b"challenge").await.unwrap();
        if read_frame(&mut read).await.ok().flatten().is_none() {
            return;
        }
        write_frame(&mut write, &[1]).await.unwrap();
        let mut rng = Rng(seed | 1);
        while let Ok(Some(frame)) = read_frame(&mut read).await {
            for _ in 0..rng.below(5) {
                tokio::task::yield_now().await;
            }
            let mut response = vec![TAG_RESPONSE];
            response.extend_from_slice(&frame[..8.min(frame.len())]);
            if write_frame(&mut write, &response).await.is_err() {
                return;
            }
        }
    });
    client_end
}

/// The bound must not trip on traffic a conforming relay produces, including
/// requests that are dropped at every kind of point and asked again. This is
/// the schedule the cancel-safety tests use, run for longer against relays
/// with pipes from 8 bytes up: every answer that comes back is the answer to
/// its own request, and the only errors are the ones that mean "reconnect".
#[tokio::test]
async fn abandoned_requests_to_a_conforming_relay_never_reach_the_bound() {
    let bob = DeviceAddr::new("+bob", 1);
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let mut conn: Option<Connection> = None;
    let (mut answered, mut abandoned, mut reconnects) = (0u32, 0u32, 0u32);
    for counter in 1..=2_000u64 {
        if conn.is_none() {
            let pipe = [8usize, 16, 64, 1024, 65536][rng.below(5) as usize];
            conn = Some(
                Connection::establish(conforming_relay(pipe, rng.next()), &bob, |_| {
                    b"+bob".to_vec()
                })
                .await
                .unwrap(),
            );
            reconnects += 1;
        }
        let live = conn.as_mut().unwrap();
        let mut request = counter.to_be_bytes().to_vec();
        request.resize(
            8 + [0usize, 10, 100, 5_000, 70_000][rng.below(5) as usize],
            0x5a,
        );
        let outcome = if rng.below(3) == 0 {
            Some(within(live.request(&request)).await)
        } else {
            at_most(live.request(&request), 1 + rng.below(6) as u32).await
        };
        match outcome {
            None => abandoned += 1,
            Some(Ok(answer)) => {
                answered += 1;
                assert_eq!(
                    answer,
                    counter.to_be_bytes(),
                    "request {counter} got another's answer"
                );
            }
            Some(Err(err)) => {
                assert!(
                    matches!(
                        err.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
                    ),
                    "request {counter} failed with {err:?}"
                );
                conn = None;
            }
        }
    }
    assert!(
        answered > 200 && abandoned > 50 && reconnects > 5,
        "answered {answered}, abandoned {abandoned}, connections {reconnects}"
    );
}
