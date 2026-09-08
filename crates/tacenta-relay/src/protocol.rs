//! The relay's request/response protocol: what a client can ask the
//! server to do, and how it is framed on the wire.
//!
//! Four operations — `Send`, `Poll`, `Ack`, and `Delivered` (the
//! delivered-to-all watermark) — and their responses. The
//! byte encoding reuses the *proven* wire codec: an envelope inside a
//! `Send` is `tacenta_wire::encode`, and the list of envelopes inside a
//! `Delivered` response is `tacenta_wire::encode_stream` (the proven
//! stream framing). The small integer/string headers around them are
//! tested here. This makes the relay transport-ready: a socket adapter
//! reads a frame, calls [`Relay::handle_bytes`], and writes the reply —
//! it needs no knowledge of the protocol itself.

use crate::{DeviceAddr, Enqueued, Queue, Relay, StoredMessage};
use tacenta_wire::{Envelope, decode, encode};

/// A client's request to the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Route `envelope` to device `to`.
    Send { to: DeviceAddr, envelope: Envelope },
    /// Ask for the envelopes waiting for `device`.
    Poll { device: DeviceAddr },
    /// Acknowledge receipt for `device` up to `up_to`.
    Ack { device: DeviceAddr, up_to: u64 },
    /// Ask how many messages have been delivered to *all* of `devices` — the
    /// minimum cursor across them. The caller supplies the device list (its
    /// own user's devices); the relay refuses if any device is not the
    /// authenticated user's. This is the `User` machine's `delivered`
    /// (decision record 0026), computed on the live per-device cursors.
    Delivered { devices: Vec<DeviceAddr> },
}

/// The relay's response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// A `Send` was accepted.
    Ok,
    /// The pending messages for a polled device — each with its sender —
    /// and the cursor position they begin at. The client acknowledges by
    /// *absolute* position, so it acks `from + messages.len()` — this is
    /// what lets a client drain its queue correctly across repeated polls.
    Delivered {
        from: u64,
        messages: Vec<StoredMessage>,
    },
    /// Whether an `Ack` was accepted (the proven `Session::ack` rule).
    Acked { accepted: bool },
    /// The delivered-to-all count for a `Delivered` request: the minimum
    /// cursor across the queried devices (0 for an empty list).
    DeliveredCount { count: u64 },
    /// The request tried to read or acknowledge a device other than the
    /// authenticated one — or query a `Delivered` watermark across a device
    /// that is not the authenticated user's. The relay enforces this by
    /// address comparison alone; the identity proof happens in the transport
    /// handshake.
    Unauthorized,
    /// A `Send` named a recipient the deployment does not know, so no queue was
    /// created for it.
    ///
    /// **Distinct from `Unauthorized` deliberately.** `Unauthorized` is about
    /// the *sender* touching a queue that is not theirs. This is about the
    /// *recipient* not existing, which is not the sender's fault and needs a
    /// different response from a client.
    ///
    /// The relay itself never returns this and stays blind: it is produced by
    /// the transport, which has the registration view, before the relay sees
    /// the request at all.
    UnknownRecipient,
    /// A `Send` was refused: the recipient already holds `MAX_PENDING`
    /// unacknowledged messages, or as many unacknowledged bytes
    /// (`MAX_QUEUE_BYTES`) — backpressure. Distinct from `Ok` so a
    /// sender can retry later rather than assume delivery, and distinct from
    /// `UnknownRecipient` because the recipient exists and is simply behind.
    QueueFull,
    /// A `Send` was refused because the single message exceeds
    /// `MAX_ENVELOPE_BYTES`. **Permanent**, unlike `QueueFull`: the same
    /// message cannot be made to fit, so a client must surface an error rather
    /// than retry as backpressure.
    TooLarge,
}

impl Relay {
    /// Dispatch a request made by the authenticated device `authorized`.
    ///
    /// `Send` may target any device (the recipient authenticates the
    /// sender cryptographically, via the session — the server does not).
    /// `Poll` and `Ack` may only touch the authenticated device's own
    /// queue; anything else is `Unauthorized`. This check is pure
    /// address comparison — no cryptography — so the relay stays blind.
    pub fn handle(&mut self, authorized: &DeviceAddr, request: Request) -> Response {
        match request {
            Request::Send { to, envelope } => match self.enqueue(&to, authorized, envelope) {
                Enqueued::Ok => Response::Ok,
                Enqueued::QueueFull => Response::QueueFull,
                Enqueued::TooLarge => Response::TooLarge,
            },
            Request::Poll { device } if device == *authorized => Response::Delivered {
                from: self.cursor(&device),
                messages: self.pending(&device).to_vec(),
            },
            Request::Ack { device, up_to } if device == *authorized => Response::Acked {
                accepted: self.ack(&device, up_to),
            },
            Request::Delivered { devices } if devices.iter().all(|d| d.user == authorized.user) => {
                Response::DeliveredCount {
                    count: devices.iter().map(|d| self.cursor(d)).min().unwrap_or(0),
                }
            }
            Request::Poll { .. } | Request::Ack { .. } | Request::Delivered { .. } => {
                Response::Unauthorized
            }
        }
    }

    /// Byte-level request handler: decode a request from the
    /// authenticated device, dispatch it, encode the response. `None` if
    /// the request bytes are malformed. This is the entry point a
    /// transport calls per frame, once the connection is authenticated.
    pub fn handle_bytes(&mut self, authorized: &DeviceAddr, request: &[u8]) -> Option<Vec<u8>> {
        let request = decode_request(request)?;
        Some(encode_response(&self.handle(authorized, request)))
    }

    /// Serialize the whole relay to bytes a caller can persist so the server
    /// survives a restart. Each queue's resident messages ride the *proven*
    /// stream framing; only the surrounding headers are new. Devices are
    /// emitted in a deterministic order so snapshots are diffable.
    ///
    /// **The format carries a version marker.** A queue has a `base` (messages
    /// compacted away) as well as a resident tail and an inner cursor, and all
    /// three must persist or a restored queue would report the wrong absolute
    /// cursor and desync every client ack. The marker lets [`Relay::restore`]
    /// still read a pre-compaction snapshot rather than treating it as corrupt
    /// and refusing to boot.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut devices: Vec<&DeviceAddr> = self.queues.keys().collect();
        devices.sort_by(|a, b| a.user.cmp(&b.user).then(a.device.cmp(&b.device)));

        let mut out = vec![SNAPSHOT_MARKER, SNAPSHOT_VERSION_2];
        put_u32(
            &mut out,
            u32::try_from(devices.len()).expect("device count fits u32"),
        );
        for device in devices {
            let queue = &self.queues[device];
            put_addr(&mut out, device);
            out.extend_from_slice(&queue.base().to_be_bytes());
            out.extend_from_slice(&(queue.inner_cursor() as u64).to_be_bytes());
            let mut log_bytes = Vec::new();
            put_messages(&mut log_bytes, queue.resident());
            put_bytes(&mut out, &log_bytes);
        }
        out
    }

    /// Reconstruct a relay from a [`Relay::snapshot`]. `None` if the bytes are
    /// malformed. Each queue is rebuilt through the proven `append`/`ack`, so
    /// the reconstructed state satisfies the same invariant nothing bypasses.
    ///
    /// Reads both the current versioned format and the pre-compaction one (no
    /// marker, absolute cursor and the whole log). A legacy snapshot restores
    /// with `base = 0`: faithful, and the delivered prefix is reclaimed on the
    /// first ack after restart rather than at load.
    pub fn restore(bytes: &[u8]) -> Option<Relay> {
        match bytes.split_first() {
            Some((&SNAPSHOT_MARKER, rest)) => {
                let (&version, rest) = rest.split_first()?;
                if version != SNAPSHOT_VERSION_2 {
                    return None;
                }
                Self::restore_v2(rest)
            }
            // No marker: the pre-compaction format, starting with the device
            // count (whose high byte is zero and so never collides with the
            // marker).
            _ => Self::restore_legacy(bytes),
        }
    }

    /// Versioned restore: per queue `[addr][u64 base][u64 inner_cursor][lp
    /// resident]`.
    fn restore_v2(bytes: &[u8]) -> Option<Relay> {
        let (count, mut rest) = take_u32(bytes)?;
        let mut relay = Relay::new();
        for _ in 0..count {
            let (device, r) = take_addr(rest)?;
            let (base_bytes, r) = r.split_at_checked(8)?;
            let base = u64::from_be_bytes(base_bytes.try_into().ok()?);
            let (cursor_bytes, r) = r.split_at_checked(8)?;
            let inner_cursor = u64::from_be_bytes(cursor_bytes.try_into().ok()?) as usize;
            let (log_bytes, r) = take_bytes(r)?;
            let (resident, log_rest) = take_messages(log_bytes)?;
            if !log_rest.is_empty() {
                return None;
            }
            rest = r;
            relay
                .queues
                .insert(device, Queue::from_parts(base, resident, inner_cursor)?);
        }
        relay.rebuild_user_bytes();
        rest.is_empty().then_some(relay)
    }

    /// Pre-versioned restore: per queue `[addr][u64 absolute_cursor][lp whole_log]`,
    /// `base = 0`. Replays the whole log and acks up to the cursor.
    fn restore_legacy(bytes: &[u8]) -> Option<Relay> {
        let (count, mut rest) = take_u32(bytes)?;
        let mut relay = Relay::new();
        for _ in 0..count {
            let (device, r) = take_addr(rest)?;
            let (cursor_bytes, r) = r.split_at_checked(8)?;
            let cursor = u64::from_be_bytes(cursor_bytes.try_into().ok()?) as usize;
            let (log_bytes, r) = take_bytes(r)?;
            let (log, log_rest) = take_messages(log_bytes)?;
            if !log_rest.is_empty() {
                return None;
            }
            rest = r;
            relay
                .queues
                .insert(device, Queue::from_parts(0, log, cursor)?);
        }
        relay.rebuild_user_bytes();
        rest.is_empty().then_some(relay)
    }
}

/// Snapshot format marker: a byte that a pre-compaction snapshot (which begins
/// with the high byte of a `u32` device count, always zero for real counts)
/// can never start with, so the two formats are distinguishable.
const SNAPSHOT_MARKER: u8 = 0x5a;

/// The snapshot format version that follows [`SNAPSHOT_MARKER`]: per-queue
/// base, inner cursor, and resident tail.
const SNAPSHOT_VERSION_2: u8 = 0x02;

/// Big-endian u32 length/value prefix helpers, matching the wire style.
fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_be_bytes(head.try_into().ok()?), rest))
}

/// Length-prefixed byte block: `[u32 len][bytes]`.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).expect("block fits u32"));
    out.extend_from_slice(bytes);
}

fn take_bytes(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = take_u32(bytes)?;
    rest.split_at_checked(len as usize)
}

fn put_addr(out: &mut Vec<u8>, addr: &DeviceAddr) {
    put_bytes(out, addr.user.as_bytes());
    put_u32(out, addr.device);
}

fn take_addr(bytes: &[u8]) -> Option<(DeviceAddr, &[u8])> {
    let (user_bytes, rest) = take_bytes(bytes)?;
    let user = String::from_utf8(user_bytes.to_vec()).ok()?;
    let (device, rest) = take_u32(rest)?;
    Some((DeviceAddr { user, device }, rest))
}

/// Encode a list of attributed messages: `[u32 count]` then, per message,
/// the sender address and the length-prefixed *proven* envelope encoding.
fn put_messages(out: &mut Vec<u8>, messages: &[StoredMessage]) {
    put_u32(
        out,
        u32::try_from(messages.len()).expect("message count fits u32"),
    );
    for m in messages {
        put_addr(out, &m.from);
        put_bytes(out, &encode(&m.envelope).expect("envelope encodes"));
    }
}

fn take_messages(bytes: &[u8]) -> Option<(Vec<StoredMessage>, &[u8])> {
    let (count, mut rest) = take_u32(bytes)?;
    // Never sized from the wire: a hostile count would ask for the world.
    let mut messages = Vec::new();
    for _ in 0..count {
        let (from, r) = take_addr(rest)?;
        let (env_bytes, r) = take_bytes(r)?;
        messages.push(StoredMessage {
            from,
            envelope: decode(env_bytes)?,
        });
        rest = r;
    }
    Some((messages, rest))
}

/// Encode a request. Tags: 1 = Send, 2 = Poll, 3 = Ack, 4 = Delivered.
pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        Request::Send { to, envelope } => {
            out.push(1);
            put_addr(&mut out, to);
            // Envelope payloads can be large; length-prefix the proven
            // encoding so the frame stays self-delimiting.
            put_bytes(&mut out, &encode(envelope).expect("envelope encodes"));
        }
        Request::Poll { device } => {
            out.push(2);
            put_addr(&mut out, device);
        }
        Request::Ack { device, up_to } => {
            out.push(3);
            put_addr(&mut out, device);
            out.extend_from_slice(&up_to.to_be_bytes());
        }
        Request::Delivered { devices } => {
            out.push(4);
            put_u32(
                &mut out,
                u32::try_from(devices.len()).expect("device count fits u32"),
            );
            for device in devices {
                put_addr(&mut out, device);
            }
        }
    }
    out
}

/// Decode a request; `None` on any malformation.
pub fn decode_request(bytes: &[u8]) -> Option<Request> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => {
            let (to, rest) = take_addr(rest)?;
            let (env_bytes, rest) = take_bytes(rest)?;
            if !rest.is_empty() {
                return None;
            }
            Some(Request::Send {
                to,
                envelope: decode(env_bytes)?,
            })
        }
        2 => {
            let (device, rest) = take_addr(rest)?;
            rest.is_empty().then_some(Request::Poll { device })
        }
        3 => {
            let (device, rest) = take_addr(rest)?;
            let (head, rest) = rest.split_at_checked(8)?;
            if !rest.is_empty() {
                return None;
            }
            Some(Request::Ack {
                device,
                up_to: u64::from_be_bytes(head.try_into().ok()?),
            })
        }
        4 => {
            let (count, mut rest) = take_u32(rest)?;
            let mut devices = Vec::new();
            for _ in 0..count {
                let (device, r) = take_addr(rest)?;
                devices.push(device);
                rest = r;
            }
            rest.is_empty().then_some(Request::Delivered { devices })
        }
        _ => None,
    }
}

/// Encode a response. Tags: 1 = Ok, 2 = Delivered, 3 = Acked,
/// 4 = Unauthorized.
pub fn encode_response(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    match response {
        Response::Ok => out.push(1),
        Response::Delivered { from, messages } => {
            out.push(2);
            out.extend_from_slice(&from.to_be_bytes());
            put_messages(&mut out, messages);
        }
        Response::Acked { accepted } => {
            out.push(3);
            out.push(u8::from(*accepted));
        }
        Response::Unauthorized => out.push(4),
        Response::DeliveredCount { count } => {
            out.push(5);
            out.extend_from_slice(&count.to_be_bytes());
        }
        Response::UnknownRecipient => out.push(6),
        Response::QueueFull => out.push(7),
        Response::TooLarge => out.push(8),
    }
    out
}

/// Decode a response; `None` on any malformation.
pub fn decode_response(bytes: &[u8]) -> Option<Response> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => rest.is_empty().then_some(Response::Ok),
        2 => {
            let (from_bytes, rest) = rest.split_at_checked(8)?;
            let (messages, rest) = take_messages(rest)?;
            rest.is_empty().then_some(Response::Delivered {
                from: u64::from_be_bytes(from_bytes.try_into().ok()?),
                messages,
            })
        }
        3 => match rest {
            [0] => Some(Response::Acked { accepted: false }),
            [1] => Some(Response::Acked { accepted: true }),
            _ => None,
        },
        4 => rest.is_empty().then_some(Response::Unauthorized),
        6 => rest.is_empty().then_some(Response::UnknownRecipient),
        7 => rest.is_empty().then_some(Response::QueueFull),
        8 => rest.is_empty().then_some(Response::TooLarge),
        5 => {
            let (count_bytes, rest) = rest.split_at_checked(8)?;
            rest.is_empty().then(|| Response::DeliveredCount {
                count: u64::from_be_bytes(count_bytes.try_into().unwrap()),
            })
        }
        _ => None,
    }
}

/// Encode an authentication response: the device claiming identity and
/// its signature over the server's challenge. Sent by the client during
/// the transport handshake; the server hands the parts to its
/// authenticator (which owns the crypto). `[addr][u32 sig len][sig]`.
pub fn encode_auth(device: &DeviceAddr, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_addr(&mut out, device);
    put_bytes(&mut out, signature);
    out
}

/// Decode an authentication response into `(device, signature)`.
pub fn decode_auth(bytes: &[u8]) -> Option<(DeviceAddr, Vec<u8>)> {
    let (device, rest) = take_addr(bytes)?;
    let (sig, rest) = take_bytes(rest)?;
    rest.is_empty().then(|| (device, sig.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_wire::Kind;

    fn env(byte: u8) -> Envelope {
        Envelope {
            kind: Kind::Dm,
            payload: vec![byte, byte, byte],
        }
    }

    fn addr() -> DeviceAddr {
        DeviceAddr::new("+alice", 7)
    }

    fn msg(from: &DeviceAddr, byte: u8) -> StoredMessage {
        StoredMessage {
            from: from.clone(),
            envelope: env(byte),
        }
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::Send {
                to: addr(),
                envelope: env(0x11),
            },
            Request::Poll { device: addr() },
            Request::Ack {
                device: addr(),
                up_to: 42,
            },
            Request::Delivered {
                devices: vec![DeviceAddr::new("+alice", 1), DeviceAddr::new("+alice", 2)],
            },
            Request::Delivered { devices: vec![] },
        ] {
            assert_eq!(decode_request(&encode_request(&r)), Some(r));
        }
    }

    #[test]
    fn responses_round_trip() {
        for r in [
            Response::Ok,
            Response::Delivered {
                from: 0,
                messages: vec![msg(&addr(), 1), msg(&addr(), 2)],
            },
            Response::Delivered {
                from: 0,
                messages: vec![],
            },
            Response::Acked { accepted: true },
            Response::Acked { accepted: false },
            Response::DeliveredCount { count: 0 },
            Response::DeliveredCount { count: 7 },
            Response::Unauthorized,
            Response::UnknownRecipient,
            Response::QueueFull,
            Response::TooLarge,
        ] {
            assert_eq!(decode_response(&encode_response(&r)), Some(r));
        }
    }

    #[test]
    fn delivered_is_the_minimum_cursor_across_a_users_devices() {
        let mut relay = Relay::new();
        let alice = DeviceAddr::new("+alice", 1);
        let d1 = DeviceAddr::new("+bob", 1);
        let d2 = DeviceAddr::new("+bob", 2);
        // Fan three messages to each device; d1 acks 3, d2 acks 1.
        for d in [&d1, &d2] {
            for b in 0..3u8 {
                relay.enqueue(d, &alice, env(b));
            }
        }
        assert!(relay.ack(&d1, 3));
        assert!(relay.ack(&d2, 1));

        // Delivered to *all* of Bob's devices = min(3, 1) = 1.
        assert_eq!(
            relay.handle(
                &d1,
                Request::Delivered {
                    devices: vec![d1.clone(), d2.clone()],
                }
            ),
            Response::DeliveredCount { count: 1 }
        );
        // A single device's own watermark is just its cursor.
        assert_eq!(
            relay.handle(
                &d1,
                Request::Delivered {
                    devices: vec![d1.clone()]
                }
            ),
            Response::DeliveredCount { count: 3 }
        );
        // Empty list is zero.
        assert_eq!(
            relay.handle(&d1, Request::Delivered { devices: vec![] }),
            Response::DeliveredCount { count: 0 }
        );
        // Querying across another user's device is refused.
        assert_eq!(
            relay.handle(
                &d1,
                Request::Delivered {
                    devices: vec![d1.clone(), DeviceAddr::new("+carol", 1)],
                }
            ),
            Response::Unauthorized
        );
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert_eq!(decode_request(&[]), None);
        assert_eq!(decode_request(&[9]), None); // unknown tag
        assert_eq!(decode_request(&[2, 0, 0, 0, 255]), None); // truncated addr
    }

    #[test]
    fn a_client_drives_the_relay_over_bytes() {
        let mut relay = Relay::new();
        let bob = DeviceAddr::new("+bob", 1);

        // Send two, over the byte protocol.
        for e in [env(0xa1), env(0xa2)] {
            let resp = relay
                .handle_bytes(
                    &bob,
                    &encode_request(&Request::Send {
                        to: bob.clone(),
                        envelope: e,
                    }),
                )
                .unwrap();
            assert_eq!(decode_response(&resp), Some(Response::Ok));
        }

        // Poll returns both.
        let resp = relay
            .handle_bytes(
                &bob,
                &encode_request(&Request::Poll {
                    device: bob.clone(),
                }),
            )
            .unwrap();
        // The poll carries each message stamped with its sender (bob, here
        // sending to himself over the authenticated connection).
        assert_eq!(
            decode_response(&resp),
            Some(Response::Delivered {
                from: 0,
                messages: vec![msg(&bob, 0xa1), msg(&bob, 0xa2)],
            })
        );

        // Ack both; the cursor advances and the queue drains.
        let resp = relay
            .handle_bytes(
                &bob,
                &encode_request(&Request::Ack {
                    device: bob.clone(),
                    up_to: 2,
                }),
            )
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Acked { accepted: true })
        );

        let resp = relay
            .handle_bytes(
                &bob,
                &encode_request(&Request::Poll {
                    device: bob.clone(),
                }),
            )
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Delivered {
                from: 2,
                messages: vec![]
            })
        );
    }

    #[test]
    fn auth_frame_round_trips() {
        let sig = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            decode_auth(&encode_auth(&addr(), &sig)),
            Some((addr(), sig))
        );
        assert_eq!(decode_auth(&[]), None);
    }

    #[test]
    fn responses_include_unauthorized() {
        assert_eq!(
            decode_response(&encode_response(&Response::Unauthorized)),
            Some(Response::Unauthorized)
        );
    }

    #[test]
    fn cannot_read_another_devices_queue() {
        let mut relay = Relay::new();
        let alice = DeviceAddr::new("+alice", 1);
        let bob = DeviceAddr::new("+bob", 1);
        relay.enqueue(&bob, &alice, env(0xff));

        // Authenticated as alice, touching bob's queue is refused.
        assert_eq!(
            relay.handle(
                &alice,
                Request::Poll {
                    device: bob.clone()
                }
            ),
            Response::Unauthorized
        );
        assert_eq!(
            relay.handle(
                &alice,
                Request::Ack {
                    device: bob.clone(),
                    up_to: 1
                }
            ),
            Response::Unauthorized
        );
        assert_eq!(relay.cursor(&bob), 0);
        // But alice may send to bob.
        assert_eq!(
            relay.handle(
                &alice,
                Request::Send {
                    to: bob,
                    envelope: env(0x01)
                }
            ),
            Response::Ok
        );
    }

    #[test]
    fn survives_a_restart() {
        let alice = DeviceAddr::new("+alice", 1);
        let bob = DeviceAddr::new("+bob", 1);

        let mut relay = Relay::new();
        relay.enqueue(&bob, &alice, env(0xb1));
        relay.enqueue(&bob, &alice, env(0xb2));
        relay.enqueue(&bob, &alice, env(0xb3));
        assert!(relay.ack(&bob, 1)); // bob has consumed one
        relay.enqueue(&alice, &bob, env(0xa1));

        // Persist, drop, and reload — as a server restart would.
        let snapshot = relay.snapshot();
        drop(relay);
        let mut relay = Relay::restore(&snapshot).expect("snapshot restores");

        // Cursors, pending, and senders survived exactly.
        assert_eq!(relay.cursor(&bob), 1);
        assert_eq!(relay.pending(&bob), &[msg(&alice, 0xb2), msg(&alice, 0xb3)]);
        assert_eq!(relay.cursor(&alice), 0);
        assert_eq!(relay.pending(&alice), &[msg(&bob, 0xa1)]);

        // The restored relay is live: it keeps operating correctly.
        assert!(relay.ack(&bob, 3));
        assert!(relay.pending(&bob).is_empty());
        relay.enqueue(&bob, &alice, env(0xb4));
        assert_eq!(relay.pending(&bob), &[msg(&alice, 0xb4)]);

        // A snapshot of the empty relay round-trips, and junk is rejected.
        assert_eq!(
            Relay::restore(&Relay::new().snapshot())
                .unwrap()
                .cursor(&bob),
            0
        );
        assert!(Relay::restore(&[0xff]).is_none());
    }

    /// A snapshot written by the pre-compaction server — no marker, absolute
    /// cursor, whole log — still restores. This is the guarantee that deploying
    /// the compaction change does not brick a running server whose
    /// `relay.snapshot` is in the old format: `load` treats a corrupt snapshot
    /// as fatal, so a format break here would stop the server booting.
    #[test]
    fn a_pre_compaction_snapshot_still_restores() {
        let bob = DeviceAddr::new("+bob", 1);
        let alice = DeviceAddr::new("+alice", 1);

        // Hand-build the legacy format: [u32 count], then per queue
        // [addr][u64 absolute_cursor][lp whole_log]. No marker byte.
        let mut legacy = Vec::new();
        put_u32(&mut legacy, 1);
        put_addr(&mut legacy, &bob);
        legacy.extend_from_slice(&1u64.to_be_bytes()); // acked one
        let mut log_bytes = Vec::new();
        put_messages(
            &mut log_bytes,
            &[msg(&alice, 0xb1), msg(&alice, 0xb2), msg(&alice, 0xb3)],
        );
        put_bytes(&mut legacy, &log_bytes);

        // The first byte is the high byte of the device count (0x00), never the
        // marker, so restore routes to the legacy path.
        assert_ne!(legacy[0], SNAPSHOT_MARKER);
        let mut relay = Relay::restore(&legacy).expect("legacy snapshot restores");

        assert_eq!(relay.cursor(&bob), 1, "absolute cursor preserved");
        assert_eq!(
            relay.pending(&bob),
            &[msg(&alice, 0xb2), msg(&alice, 0xb3)],
            "the undelivered tail is intact"
        );
        // And it is live: the next ack compacts, freeing the delivered prefix a
        // legacy snapshot could not have dropped.
        assert!(relay.ack(&bob, 3));
        assert!(relay.pending(&bob).is_empty());
    }
}
