//! A cryptographically blind message relay.
//!
//! The relay routes opaque encrypted envelopes between devices. It holds
//! one per-device queue — a `tacenta_state::Session`, the delivery
//! machine proven in `verification/` — and offers enqueue / pending /
//! ack. It never inspects an envelope's payload, and it *cannot*: this
//! crate does not depend on `tacenta-core` or on any cryptography, only
//! on the wire format and the delivery machine (decision record 0012).
//! The end-to-end encryption trust model is therefore structural — the
//! server has no code path to a plaintext.
//!
//! Routing metadata — which device a message is for, and which
//! authenticated device it is from — is passed explicitly to `enqueue`,
//! modeling a transport that carries a server-visible recipient and
//! sender alongside the server-blind ciphertext. The recipient needs the
//! sender to attribute and decrypt a message (decision record 0027).
//! In-memory at runtime; `snapshot`/`restore` let a server persist it.

mod protocol;

pub use protocol::{
    Request, Response, decode_auth, decode_request, decode_response, encode_auth, encode_request,
    encode_response,
};

use std::collections::HashMap;
use tacenta_state::Session;
use tacenta_wire::Envelope;

/// A queued message together with the device that sent it. The relay
/// stamps the *authenticated* sender onto every message it routes, so the
/// recipient learns who a message is from — which it needs to decrypt it,
/// even a first-contact message from a device it has no session with yet.
/// The sender is routing metadata (the relay authenticated the connection
/// that sent it); the envelope payload stays opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    pub from: DeviceAddr,
    pub envelope: Envelope,
}

impl StoredMessage {
    /// The heap this message holds, for the per-queue byte budget. The
    /// ciphertext payload dominates; the sender handle is counted so a flood of
    /// tiny-payload messages from a long handle is still bounded. An estimate,
    /// not the exact serialized size — the budget only needs to bound growth,
    /// not account for every byte.
    fn byte_len(&self) -> usize {
        self.envelope.payload.len() + self.from.user.len()
    }
}

/// A device's routing address: which user, which of their devices. This
/// is the relay's own routing key — deliberately not the crypto layer's
/// address type, since the relay knows nothing of the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceAddr {
    pub user: String,
    pub device: u32,
}

impl DeviceAddr {
    pub fn new(user: impl Into<String>, device: u32) -> DeviceAddr {
        DeviceAddr {
            user: user.into(),
            device,
        }
    }
}

/// The most unacknowledged messages one device's queue will hold before a
/// `Send` to it is refused (the backpressure half).
///
/// This bounds an attacker — or a broken client — that never polls: without it,
/// a recipient's queue grows without limit while nothing drains it. It is a cap
/// on the *unacknowledged* backlog, deliberately not on lifetime traffic: a cap
/// on lifetime traffic would turn "memory grows" into "the device can never
/// receive again", which is worse. 65,536 undelivered messages is far above any
/// honest offline accumulation and far below a memory problem.
pub const MAX_PENDING: usize = 1 << 16;

/// The largest a single stored message may be, in bytes. A `Send` over this is
/// refused **permanently** ([`Enqueued::TooLarge`]) rather than queued: it would
/// never fit a sane queue, so a retry cannot help.
///
/// This is the per-envelope half of the byte budget. It sits below the transport's `MAX_FRAME_LEN` (16 MiB), which
/// bounds one wire frame; this bounds one *stored* message, the finer limit. A
/// baseline value — the exact ceiling is a deployment tuning, and a product that
/// carries inline media rather than out-of-band blobs would raise it with a
/// reason.
pub const MAX_ENVELOPE_BYTES: usize = 1 << 20;

/// The most **unacknowledged bytes** one device's queue will hold before a
/// `Send` to it is refused as backpressure ([`Enqueued::QueueFull`]).
///
/// [`MAX_PENDING`] bounds the *count* of undelivered messages; it says nothing
/// about their size, so a count cap alone would leave worst-case retained
/// bytes at `MAX_PENDING × MAX_ENVELOPE_BYTES` — far too high for a public
/// listener. Whichever limit a queue reaches first — the count or
/// this byte budget — refuses further sends. Like `MAX_PENDING` it bounds the
/// *unacknowledged* backlog, not lifetime traffic, so a draining recipient is
/// never permanently shut out. A baseline value, tunable per deployment.
///
/// **Scope: per queue (per device).** A user's devices are additionally bounded
/// in aggregate by [`MAX_USER_BYTES`], and total server memory across *all* users
/// by [`MAX_TOTAL_BYTES`] — the layer that closes the cheap-many-handles memory
/// exhaustion.
pub const MAX_QUEUE_BYTES: usize = 64 << 20;

/// The most **unacknowledged bytes across all of one user's device queues**
/// before a `Send` to any of them is refused as backpressure
/// ([`Enqueued::QueueFull`]).
///
/// [`MAX_QUEUE_BYTES`] bounds a single device's queue; without this, a user with
/// many registered devices multiplies that. This caps the user's total
/// regardless of device count. It is at least `MAX_QUEUE_BYTES`, so one device
/// can still fill its own queue. A baseline value, tunable per deployment. The
/// aggregate across *distinct* users is bounded above by [`MAX_TOTAL_BYTES`].
pub const MAX_USER_BYTES: usize = 128 << 20;

/// The **default** ceiling on unacknowledged bytes the whole relay will hold,
/// summed across every user and device, before *any* further `Send` is refused as
/// backpressure ([`Enqueued::QueueFull`]). A deployment overrides it with
/// [`Relay::with_max_total_bytes`]; this const is what a relay uses unconfigured.
///
/// The per-device ([`MAX_QUEUE_BYTES`]) and per-user ([`MAX_USER_BYTES`]) budgets
/// each bound *one* principal's backlog, but neither bounds the number of
/// principals. On a **public self-service** relay, where registering a fresh user
/// handle is cheap, worst-case retained memory would otherwise be
/// `registered users × MAX_USER_BYTES` — unbounded in practice. This is the
/// node's hard ceiling on total resident
/// undelivered bytes: once it is reached the relay refuses new sends globally
/// until acked messages drain, so memory is bounded regardless of how many users
/// exist.
///
/// This closes the *memory* half of the cheap-handle problem, not the whole of
/// it: at the ceiling the refusal is **global** backpressure, so many registered
/// handles can still degrade availability up to this bound for everyone. Bounding
/// that further is admission control — making a handle cost something — which is
/// registration policy, not the relay's job, and is out of this crate's scope.
///
/// **Set this from the node's RAM**, not from the per-user figure: it is a
/// safety ceiling on the process, and this default (4 GiB) is a conservative
/// placeholder a deployment is expected to raise or lower to fit its box, via
/// [`Relay::with_max_total_bytes`] (which enforces the floor below). It must be at
/// least [`MAX_USER_BYTES`] so a single user can still reach their own budget.
/// Held as `u64` rather than `usize` because a real relay's budget can exceed a
/// 32-bit address space even where `usize` cannot.
pub const MAX_TOTAL_BYTES: u64 = 4 << 30;

/// Whether a `Send` was queued or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// Appended to the recipient's queue.
    Ok,
    /// Refused: the recipient already holds [`MAX_PENDING`] unacknowledged
    /// messages, or as many unacknowledged bytes ([`MAX_QUEUE_BYTES`]). The
    /// sender should treat this as **backpressure** and retry later, once the
    /// recipient drains.
    QueueFull,
    /// Refused: this one message exceeds [`MAX_ENVELOPE_BYTES`]. **Permanent** —
    /// unlike `QueueFull`, retrying the same message cannot succeed, so the
    /// sender must not treat it as backpressure.
    TooLarge,
}

/// One device's queue: the proven [`Session`] delivery machine, plus a `base`
/// offset so acknowledged messages can be **dropped** while the cursor a client
/// sees stays absolute.
///
/// **This is the compaction the proofs do not cover, kept where they are not.**
/// `Session` is the machine `StateRefinement.lean` proves: append-only log,
/// monotone cursor, no loss, no replay. Those theorems say nothing about
/// resource use, and the log grows forever under them. Rather than
/// reopen the proofs to teach the log to forget, this wraps `Session`: on ack
/// it rebuilds the inner session from only its *pending* tail — through the
/// proven `append`, so the reconstructed session satisfies the same invariant —
/// and adds the dropped count to `base`. The client keeps acking absolute
/// positions; the wire never sees the base.
///
/// The base arithmetic is new and **is not proven** — it is straight-line
/// translation, covered by the property tests below rather than by Lean. That
/// boundary is the honest cost of not reopening `StateRefinement.lean` to fix a
/// memory problem it was never about.
#[derive(Debug, Clone)]
struct Queue {
    /// Absolute count of messages compacted away. A client's cursor is
    /// `base + inner.cursor()`; `inner` only ever holds the tail from `base` on.
    base: u64,
    inner: Session<StoredMessage>,
    /// Sum of [`StoredMessage::byte_len`] over the pending (unacknowledged) tail,
    /// for the [`MAX_QUEUE_BYTES`] budget. Maintained incrementally on enqueue
    /// and recomputed on ack (which shrinks the tail), so the budget check on the
    /// enqueue hot path stays O(1) — summing the tail per enqueue would be
    /// O(n²) to fill a queue, an amplification an attacker would enjoy.
    pending_bytes: usize,
}

// Manual, not derived: the derived `Default` would demand `StoredMessage:
// Default` (the derive bounds every field's type parameter), which the message
// type does not and should not implement. A queue's default is empty.
impl Default for Queue {
    fn default() -> Queue {
        Queue {
            base: 0,
            inner: Session::new(),
            pending_bytes: 0,
        }
    }
}

impl Queue {
    fn enqueue(&mut self, message: StoredMessage) -> Enqueued {
        let size = message.byte_len();
        // Per-envelope cap first: a message that can never fit is refused
        // permanently, not as backpressure.
        if size > MAX_ENVELOPE_BYTES {
            return Enqueued::TooLarge;
        }
        // Then the count and byte budgets — whichever binds first is backpressure.
        if self.inner.pending().len() >= MAX_PENDING
            || self.pending_bytes.saturating_add(size) > MAX_QUEUE_BYTES
        {
            return Enqueued::QueueFull;
        }
        self.inner.append(message);
        self.pending_bytes += size;
        Enqueued::Ok
    }

    fn pending(&self) -> &[StoredMessage] {
        self.inner.pending()
    }

    /// The absolute acknowledgment cursor: messages this device has confirmed
    /// across the queue's whole life, including those since compacted away.
    fn cursor(&self) -> u64 {
        self.base + self.inner.cursor() as u64
    }

    /// Acknowledge up to the **absolute** position `up_to`. Accepts on the
    /// proven `Session::ack` rule (strictly advancing, within the resident
    /// tail), then compacts. An `up_to` at or below `base` is a stale or
    /// duplicate ack of already-dropped messages and is refused.
    fn ack(&mut self, up_to: u64) -> bool {
        let Some(inner_n) = up_to.checked_sub(self.base) else {
            return false;
        };
        let accepted = self.inner.ack(inner_n as usize);
        if accepted {
            self.compact();
            // The acked prefix has left the pending tail; recount from what
            // remains. O(remaining pending), off the enqueue hot path.
            self.pending_bytes = self
                .inner
                .pending()
                .iter()
                .map(StoredMessage::byte_len)
                .sum();
        }
        accepted
    }

    /// Drop the acknowledged prefix, moving its count into `base`. Rebuilds the
    /// inner session from its pending tail through the proven `append`, so the
    /// result is a valid `Session` the invariant still holds for.
    fn compact(&mut self) {
        let acked = self.inner.cursor();
        if acked == 0 {
            return;
        }
        let mut rebuilt = Session::new();
        for message in self.inner.pending() {
            rebuilt.append(message.clone());
        }
        self.inner = rebuilt;
        self.base += acked as u64;
    }

    /// The resident (post-compaction) messages, for snapshotting.
    fn resident(&self) -> &[StoredMessage] {
        self.inner.log()
    }

    /// How many messages are resident. After a full ack this is zero, which is
    /// the backpressure property. Test-only: the tests assert the memory is
    /// actually freed, which is not observable through the delivery API.
    #[cfg(test)]
    fn retained(&self) -> usize {
        self.inner.retained()
    }

    /// Messages compacted away, for a snapshot to persist.
    fn base(&self) -> u64 {
        self.base
    }

    /// How many *resident* messages are acknowledged (the inner cursor, not the
    /// absolute one), for a snapshot to persist.
    fn inner_cursor(&self) -> usize {
        self.inner.cursor()
    }

    /// Rebuild a queue from persisted parts: the compacted `base`, the resident
    /// tail, and how many of that tail are acknowledged. Replays through the
    /// proven `append`/`ack`, so the reconstructed session satisfies the same
    /// invariant. `None` if the acknowledged count exceeds the tail.
    fn from_parts(base: u64, resident: Vec<StoredMessage>, inner_cursor: usize) -> Option<Queue> {
        if inner_cursor > resident.len() {
            return None;
        }
        let mut inner = Session::new();
        for message in resident {
            inner.append(message);
        }
        if inner_cursor > 0 && !inner.ack(inner_cursor) {
            return None;
        }
        let pending_bytes = inner.pending().iter().map(StoredMessage::byte_len).sum();
        Some(Queue {
            base,
            inner,
            pending_bytes,
        })
    }
}

/// The relay: one delivery queue per device. Each queue's delivery behavior —
/// no loss, no replay, a cursor that never rewinds — is the proven `Session`
/// machine; the relay is thin routing glue over it, plus the compaction and
/// backpressure `Session` does not model.
#[derive(Debug)]
pub struct Relay {
    queues: HashMap<DeviceAddr, Queue>,
    /// Unacknowledged bytes summed across all of a user's device queues, for the
    /// [`MAX_USER_BYTES`] budget. A derived index over `queues`, maintained on
    /// enqueue and ack so the per-user check stays O(1); rebuilt on restore. The
    /// invariant `user_bytes[u] == Σ queues[(u,·)].pending_bytes` is pinned by
    /// `user_bytes_tracks_the_true_per_user_sum`.
    user_bytes: HashMap<String, usize>,
    /// Unacknowledged bytes summed across **every** queue, for the node ceiling
    /// (`max_total_bytes`). Like `user_bytes` it is a derived index over `queues`,
    /// maintained on enqueue and ack and rebuilt on restore;
    /// `total_bytes == Σ queues[·].pending_bytes`. Held as `u64` to match the
    /// ceiling, which can exceed a 32-bit `usize`.
    total_bytes: u64,
    /// The node's ceiling on `total_bytes`, defaulting to [`MAX_TOTAL_BYTES`].
    /// Configurable rather than a bare `const` because its right value is
    /// per-deployment — a function of the node's RAM — and a deployment sets it
    /// with [`Relay::with_max_total_bytes`]. It is *not* persisted: a restored
    /// relay adopts the running node's configured ceiling, not the one in effect
    /// when the snapshot was taken.
    max_total_bytes: u64,
}

impl Default for Relay {
    fn default() -> Relay {
        Relay {
            queues: HashMap::new(),
            user_bytes: HashMap::new(),
            total_bytes: 0,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }
}

impl Relay {
    pub fn new() -> Relay {
        Relay::default()
    }

    /// Set the node-wide memory ceiling (default [`MAX_TOTAL_BYTES`]). Panics if
    /// `limit` is below [`MAX_USER_BYTES`], which would make a single user's own
    /// budget unreachable — a misconfiguration, not a runtime condition.
    pub fn with_max_total_bytes(mut self, limit: u64) -> Relay {
        assert!(
            limit >= MAX_USER_BYTES as u64,
            "the global ceiling must be at least MAX_USER_BYTES so one user can reach their budget"
        );
        self.max_total_bytes = limit;
        self
    }

    /// Enqueue an envelope for device `to`, from device `from`, creating the
    /// queue on first use. Refused if the message exceeds [`MAX_ENVELOPE_BYTES`]
    /// ([`Enqueued::TooLarge`], permanent), or as backpressure
    /// ([`Enqueued::QueueFull`]) if it would put the recipient over
    /// [`MAX_PENDING`] messages, [`MAX_QUEUE_BYTES`] in that one queue,
    /// [`MAX_USER_BYTES`] across all the user's queues, or [`MAX_TOTAL_BYTES`]
    /// across the whole relay. The payload's *size*
    /// bounds the queues, but its *contents* are never examined — only the sender
    /// is recorded, so the recipient can attribute (and decrypt) it.
    pub fn enqueue(&mut self, to: &DeviceAddr, from: &DeviceAddr, envelope: Envelope) -> Enqueued {
        let message = StoredMessage {
            from: from.clone(),
            envelope,
        };
        let size = message.byte_len();
        // Per-envelope cap first (permanent, and it must win over the transient
        // budgets so a too-large message is never mistaken for backpressure).
        if size > MAX_ENVELOPE_BYTES {
            return Enqueued::TooLarge;
        }
        // Global node ceiling, across every user — the coarsest safety limit, so
        // it is checked before the per-principal budgets.
        if self.total_bytes.saturating_add(size as u64) > self.max_total_bytes {
            return Enqueued::QueueFull;
        }
        // Per-user aggregate budget, across the user's devices.
        let user_total = self.user_bytes.get(&to.user).copied().unwrap_or(0);
        if user_total.saturating_add(size) > MAX_USER_BYTES {
            return Enqueued::QueueFull;
        }
        // Per-device count and byte budgets live in the queue.
        let result = self.queues.entry(to.clone()).or_default().enqueue(message);
        if matches!(result, Enqueued::Ok) {
            *self.user_bytes.entry(to.user.clone()).or_insert(0) += size;
            self.total_bytes += size as u64;
        }
        result
    }

    /// The messages waiting for a device that it has not yet acknowledged,
    /// oldest first, each with its sender. Empty for an unknown device.
    pub fn pending(&self, device: &DeviceAddr) -> &[StoredMessage] {
        self.queues.get(device).map(Queue::pending).unwrap_or(&[])
    }

    /// A device's **absolute** acknowledgment cursor: how many of its queued
    /// envelopes it has confirmed across the queue's whole life, compacted
    /// messages included. Zero for an unknown device.
    pub fn cursor(&self, device: &DeviceAddr) -> u64 {
        self.queues.get(device).map_or(0, Queue::cursor)
    }

    /// A device acknowledges receipt up to absolute position `up_to`. Returns
    /// whether the acknowledgment was accepted (the proven `Session::ack` rule:
    /// strictly advancing and within the resident tail). `false` for an unknown
    /// device. Accepting an ack also compacts the queue, freeing the delivered
    /// prefix.
    pub fn ack(&mut self, device: &DeviceAddr, up_to: u64) -> bool {
        let Some(queue) = self.queues.get_mut(device) else {
            return false;
        };
        let before = queue.pending_bytes;
        if !queue.ack(up_to) {
            return false;
        }
        // Bytes the ack freed from this queue leave the user's aggregate too.
        let freed = before - queue.pending_bytes; // last use of the queue borrow
        if let Some(user) = self.user_bytes.get_mut(&device.user) {
            *user = user.saturating_sub(freed);
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed as u64);
        true
    }

    /// Recompute the per-user byte index from the queues. Used after a restore,
    /// which rebuilds `queues` directly.
    fn rebuild_user_bytes(&mut self) {
        let mut totals: HashMap<String, usize> = HashMap::new();
        let mut grand_total: u64 = 0;
        for (addr, queue) in &self.queues {
            *totals.entry(addr.user.clone()).or_insert(0) += queue.pending_bytes;
            grand_total += queue.pending_bytes as u64;
        }
        self.user_bytes = totals;
        self.total_bytes = grand_total;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_wire::Kind;

    fn env(byte: u8) -> Envelope {
        Envelope {
            kind: Kind::Dm,
            payload: vec![byte],
        }
    }

    #[test]
    fn routes_and_acknowledges_per_device() {
        let mut relay = Relay::new();
        let alice = DeviceAddr::new("+alice", 1);
        let bob1 = DeviceAddr::new("+bob", 1);
        let bob2 = DeviceAddr::new("+bob", 2);

        relay.enqueue(&bob1, &alice, env(0xa1));
        relay.enqueue(&bob1, &alice, env(0xa2));
        relay.enqueue(&bob2, &alice, env(0xb1));

        // Queues are independent per device, and record the sender.
        assert_eq!(relay.pending(&bob1).len(), 2);
        assert_eq!(relay.pending(&bob1)[0].from, alice);
        assert_eq!(relay.pending(&bob2).len(), 1);
        assert_eq!(relay.pending(&DeviceAddr::new("+nobody", 9)).len(), 0);

        // Bob's device 1 acknowledges the first message.
        assert!(relay.ack(&bob1, 1));
        assert_eq!(relay.cursor(&bob1), 1);
        assert_eq!(relay.pending(&bob1).len(), 1);
        // Device 2 is untouched.
        assert_eq!(relay.cursor(&bob2), 0);

        // A stale ack (not advancing) and an over-long ack are rejected.
        assert!(!relay.ack(&bob1, 1));
        assert!(!relay.ack(&bob1, 9));
        assert!(!relay.ack(&DeviceAddr::new("+nobody", 9), 1));
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use tacenta_wire::Kind;

    fn env64() -> Envelope {
        Envelope {
            kind: Kind::Dm,
            payload: vec![0u8; 64],
        }
    }

    /// **Acknowledged messages are freed.** `ack` advances a cursor; without
    /// compaction the log would only grow, and a device that had acknowledged
    /// everything would still hold every envelope. Compaction drops the
    /// delivered prefix, so after a full ack nothing is resident — while the
    /// absolute cursor is preserved.
    #[test]
    fn acknowledged_messages_are_freed_by_compaction() {
        let mut relay = Relay::new();
        let to = DeviceAddr::new("bob", 1);
        let from = DeviceAddr::new("alice", 1);

        for _ in 0..1_000 {
            relay.enqueue(&to, &from, env64());
        }
        assert!(relay.ack(&to, 1_000));
        assert_eq!(relay.pending(&to).len(), 0, "nothing is pending");
        assert_eq!(
            relay.queues.get(&to).map(Queue::retained),
            Some(0),
            "acknowledged envelopes are dropped, not retained"
        );
        // The cursor a client sees is absolute and unchanged by compaction.
        assert_eq!(relay.cursor(&to), 1_000);
    }

    /// Compaction is transparent across a partial ack: only the delivered prefix
    /// is freed, the pending tail survives, and the absolute cursor is exact.
    #[test]
    fn compaction_frees_only_the_delivered_prefix() {
        let mut relay = Relay::new();
        let to = DeviceAddr::new("bob", 1);
        let from = DeviceAddr::new("alice", 1);

        for _ in 0..10 {
            relay.enqueue(&to, &from, env64());
        }
        // Acknowledge the first 6; 4 remain pending.
        assert!(relay.ack(&to, 6));
        assert_eq!(relay.cursor(&to), 6, "absolute cursor is preserved");
        assert_eq!(relay.pending(&to).len(), 4, "the tail survives");
        assert_eq!(
            relay.queues.get(&to).map(Queue::retained),
            Some(4),
            "only the four undelivered messages are resident"
        );

        // Acknowledging the rest (absolute 10) frees everything.
        assert!(relay.ack(&to, 10));
        assert_eq!(relay.cursor(&to), 10);
        assert_eq!(relay.queues.get(&to).map(Queue::retained), Some(0));

        // A stale ack below the base is refused, not underflowed.
        assert!(!relay.ack(&to, 3));
    }

    /// The unacknowledged backlog is bounded: once a recipient holds
    /// `MAX_PENDING` undelivered messages, further sends are refused until it
    /// drains. Draining (an ack) frees room again.
    #[test]
    fn the_pending_backlog_is_capped() {
        let mut relay = Relay::new();
        let to = DeviceAddr::new("bob", 1);
        let from = DeviceAddr::new("alice", 1);

        for _ in 0..MAX_PENDING {
            assert_eq!(relay.enqueue(&to, &from, env64()), Enqueued::Ok);
        }
        assert_eq!(
            relay.enqueue(&to, &from, env64()),
            Enqueued::QueueFull,
            "the cap refuses the message past the limit"
        );

        // Bob acknowledges half; that many slots open back up.
        let half = (MAX_PENDING / 2) as u64;
        assert!(relay.ack(&to, half));
        assert_eq!(
            relay.enqueue(&to, &from, env64()),
            Enqueued::Ok,
            "draining the backlog reopens the queue"
        );
    }

    fn payload(len: usize) -> Envelope {
        Envelope {
            kind: Kind::Dm,
            payload: vec![0u8; len],
        }
    }

    /// **The per-envelope cap is permanent, not backpressure.** A single
    /// message over `MAX_ENVELOPE_BYTES` can never fit, so it is refused as
    /// `TooLarge` — distinct from `QueueFull`, which a sender retries. A message
    /// under the cap is accepted.
    #[test]
    fn an_oversized_message_is_refused_as_too_large() {
        let mut relay = Relay::new();
        let to = DeviceAddr::new("bob", 1);
        let from = DeviceAddr::new("alice", 1);

        assert_eq!(
            relay.enqueue(&to, &from, payload(MAX_ENVELOPE_BYTES / 2)),
            Enqueued::Ok,
            "a message under the per-envelope cap is queued"
        );
        assert_eq!(
            relay.enqueue(&to, &from, payload(MAX_ENVELOPE_BYTES + 1)),
            Enqueued::TooLarge,
            "a message over the per-envelope cap is refused permanently"
        );
    }

    /// **The byte budget bounds a queue below the count cap.**
    /// `MAX_PENDING` alone would let a queue hold `MAX_PENDING` maximal messages —
    /// gigabytes. With the byte budget, far fewer large messages fit, and the
    /// refusal is `QueueFull` (backpressure). Draining frees the byte room again.
    #[test]
    fn the_byte_budget_bounds_the_queue_below_the_count_cap() {
        let mut relay = Relay::new();
        let to = DeviceAddr::new("bob", 1);
        let from = DeviceAddr::new("alice", 1);

        // Messages just under the per-envelope cap; the byte budget binds first.
        let each = MAX_ENVELOPE_BYTES - 64;
        let mut accepted = 0usize;
        loop {
            match relay.enqueue(&to, &from, payload(each)) {
                Enqueued::Ok => accepted += 1,
                Enqueued::QueueFull => break,
                Enqueued::TooLarge => panic!("under the per-envelope cap"),
            }
            assert!(
                accepted < MAX_PENDING,
                "the byte budget must bind before the count cap"
            );
        }
        // Roughly MAX_QUEUE_BYTES / message-size messages fit — dozens, not the
        // 65,536 the count cap alone would have allowed.
        assert!(accepted >= (MAX_QUEUE_BYTES / MAX_ENVELOPE_BYTES) - 1);
        assert!(accepted <= MAX_QUEUE_BYTES / each);

        // Draining the whole backlog frees the byte budget: a send is accepted.
        assert!(relay.ack(&to, accepted as u64));
        assert_eq!(
            relay.enqueue(&to, &from, payload(each)),
            Enqueued::Ok,
            "acking the backlog frees byte-budget room"
        );
    }

    /// **The per-user budget bounds a user's devices in aggregate.**
    /// `MAX_QUEUE_BYTES` bounds one device; without a per-user cap a user with
    /// many devices multiplies it. Filling two of bob's devices to their queue
    /// caps reaches `MAX_USER_BYTES`, so a *third* device — its own queue empty —
    /// is refused: the refusal is the user budget, not the device's. A different
    /// user is unaffected, and draining one of bob's devices frees his budget.
    #[test]
    fn the_per_user_budget_bounds_a_users_devices_in_aggregate() {
        let mut relay = Relay::new();
        let from = DeviceAddr::new("alice", 1);
        let each = MAX_ENVELOPE_BYTES - 64;
        let d1 = DeviceAddr::new("bob", 1);
        let d2 = DeviceAddr::new("bob", 2);
        let d3 = DeviceAddr::new("bob", 3);

        // Fill bob's first two devices to their per-device cap; together that is
        // MAX_USER_BYTES (two × MAX_QUEUE_BYTES).
        for d in [&d1, &d2] {
            while let Enqueued::Ok = relay.enqueue(d, &from, payload(each)) {}
        }

        // A third device is refused though its own queue is empty — the user
        // budget, not this device's, is the binding limit.
        assert_eq!(
            relay.enqueue(&d3, &from, payload(each)),
            Enqueued::QueueFull
        );
        assert_eq!(
            relay.pending(&d3).len(),
            0,
            "the refusal is the user budget, not this device's queue"
        );

        // A different user is unaffected by bob's budget.
        let carol = DeviceAddr::new("carol", 1);
        assert_eq!(relay.enqueue(&carol, &from, payload(each)), Enqueued::Ok);

        // Draining one of bob's devices frees his user budget for the third.
        let acked = relay.pending(&d1).len() as u64;
        assert!(relay.ack(&d1, acked));
        assert_eq!(
            relay.enqueue(&d3, &from, payload(each)),
            Enqueued::Ok,
            "draining a device frees the user budget"
        );
    }

    /// **Invariants: `pending_bytes` equals the true
    /// sum over each queue's pending tail, and `user_bytes[u]` equals the sum of
    /// that user's queues' `pending_bytes` — after any sequence of operations.**
    /// Both budgets are only as trustworthy as those derived fields, maintained
    /// incrementally on enqueue and ack; a future mutation path that forgot one
    /// would let a budget drift silently — too permissive (a DoS) or too strict
    /// (false `QueueFull`). This drives a deterministic pseudo-random mix over two
    /// devices of one user and recomputes both from scratch every step.
    #[test]
    fn pending_and_user_bytes_track_the_true_sums() {
        let mut relay = Relay::new();
        let from = DeviceAddr::new("alice", 1);
        let devices = [DeviceAddr::new("bob", 1), DeviceAddr::new("bob", 2)];
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        for _ in 0..4000 {
            let to = &devices[next() % devices.len()];
            if next() % 3 == 0 {
                let cursor = relay.cursor(to);
                let pending = relay.pending(to).len() as u64;
                if pending > 0 {
                    let up_to = cursor + 1 + (next() as u64 % pending);
                    relay.ack(to, up_to);
                }
            } else {
                // Small messages so the byte/count caps do not bind here; the
                // cap behaviour is covered by the tests above.
                relay.enqueue(to, &from, payload(next() % 512 + 1));
            }
            // Per-queue invariant.
            for (addr, q) in &relay.queues {
                let sum: usize = q.pending().iter().map(StoredMessage::byte_len).sum();
                assert_eq!(q.pending_bytes, sum, "pending_bytes drifted at {addr:?}");
            }
            // Per-user invariant: the index equals the sum over the user's queues.
            let bob_sum: usize = relay
                .queues
                .iter()
                .filter(|(a, _)| a.user == "bob")
                .map(|(_, q)| q.pending_bytes)
                .sum();
            assert_eq!(
                relay.user_bytes.get("bob").copied().unwrap_or(0),
                bob_sum,
                "user_bytes drifted from the true per-user sum"
            );
            // Global invariant: total_bytes equals the sum over every queue.
            let grand: u64 = relay.queues.values().map(|q| q.pending_bytes as u64).sum();
            assert_eq!(
                relay.total_bytes, grand,
                "total_bytes drifted from the true relay-wide sum"
            );
        }
    }

    /// **The global ceiling bounds total relay memory across distinct users.**
    /// Neither the per-device nor the per-user budget bounds the *number* of
    /// principals, so on a public self-service relay
    /// `registered users × MAX_USER_BYTES` would be unbounded. Fill
    /// distinct single-device users until a *fresh* one — its own budget empty —
    /// is refused on its very first message: that refusal can only be the global
    /// ceiling. Total memory stays under the ceiling, the admitted user count is a
    /// handful rather than the thousand the loop offered, and draining an existing
    /// user lifts the refusal. Runs against a configured ceiling
    /// ([`MAX_USER_BYTES`], the same ~128 MiB footprint the per-user test uses),
    /// not the multi-GiB production default.
    #[test]
    fn the_global_budget_bounds_the_whole_relay_across_users() {
        let ceiling = MAX_USER_BYTES as u64;
        let mut relay = Relay::new().with_max_total_bytes(ceiling);
        let from = DeviceAddr::new("sender", 1);
        let each = MAX_ENVELOPE_BYTES - 64;

        let mut saturated = 0usize;
        let mut global_refused = false;
        for u in 0..1000usize {
            let to = DeviceAddr::new(format!("user{u}"), 1);
            // A fresh user's first message is under every per-principal cap, so a
            // QueueFull here can *only* be the global ceiling — confirmed by the
            // queue staying empty.
            if relay.enqueue(&to, &from, payload(each)) == Enqueued::QueueFull {
                assert_eq!(
                    relay.pending(&to).len(),
                    0,
                    "a fresh user's refusal is the global ceiling, not its own budget"
                );
                global_refused = true;
                break;
            }
            // Fill this user's single device as far as it will go, then move on.
            while relay.enqueue(&to, &from, payload(each)) == Enqueued::Ok {}
            saturated += 1;
        }
        assert!(
            global_refused,
            "the global ceiling must eventually refuse a fresh user"
        );

        // Memory stayed under the ceiling, and the admitted user count is bounded
        // to a handful — not the thousand the loop offered, which is the point.
        assert!(
            relay.total_bytes <= ceiling,
            "total_bytes {} exceeded the ceiling {ceiling}",
            relay.total_bytes
        );
        assert!(
            (1..=(ceiling / MAX_QUEUE_BYTES as u64) as usize + 1).contains(&saturated),
            "admitted {saturated} users; the ceiling bounds this to a handful"
        );

        // A newcomer stays refused while the relay is full, and is admitted once
        // an existing user drains and frees global room.
        let newcomer = DeviceAddr::new("newcomer", 1);
        assert_eq!(
            relay.enqueue(&newcomer, &from, payload(each)),
            Enqueued::QueueFull,
            "the global ceiling refuses even a user with an empty budget"
        );
        let victim = DeviceAddr::new("user0", 1);
        let acked = relay.pending(&victim).len() as u64;
        assert!(acked > 0 && relay.ack(&victim, acked));
        assert_eq!(
            relay.enqueue(&newcomer, &from, payload(each)),
            Enqueued::Ok,
            "draining a user frees the global ceiling"
        );
    }
}
