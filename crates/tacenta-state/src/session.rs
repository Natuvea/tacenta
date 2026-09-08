//! Per-device session state. Mirrors `Tacenta.Session` in the spec.
//!
//! One `Session` per device: an append-only log of messages and a
//! cursor counting how many the device has acknowledged. Acks are
//! cumulative and strictly monotone; an ack that does not advance the
//! cursor, or that claims more than the log holds, is rejected and
//! leaves the state untouched.
//!
//! Invariant (spec: `Session.valid`): `cursor <= log.len()` — upheld
//! because `append` only grows the log and `ack` bounds-checks before
//! moving the cursor.

/// Per-device delivery state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Session<T> {
    log: Vec<T>,
    cursor: usize,
}

impl<T> Session<T> {
    /// The fresh session: empty log, nothing acknowledged.
    pub fn new() -> Session<T> {
        Session {
            log: Vec::new(),
            cursor: 0,
        }
    }

    /// The full append-only log, delivered and pending alike.
    pub fn log(&self) -> &[T] {
        &self.log
    }

    /// How many messages this device has acknowledged.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Messages appended but not yet acknowledged, oldest first.
    ///
    /// Indexing is safe by the invariant `cursor <= log.len()`; the
    /// translation proves this cannot panic on any reachable state.
    pub fn pending(&self) -> &[T] {
        &self.log[self.cursor..]
    }

    /// How many messages the log holds, acknowledged or not.
    ///
    /// **Not the same as `pending().len()`, and the difference is the point.**
    /// `ack` advances the cursor and never truncates, so this is every message
    /// ever appended. Exposed so a test can observe the growth rather than
    /// describe it.
    pub fn retained(&self) -> usize {
        self.log.len()
    }

    /// Append a message to the log. Always allowed; never touches the
    /// cursor (spec: `append`, `append_cursor`).
    pub fn append(&mut self, e: T) {
        self.log.push(e);
    }

    /// Acknowledge everything up to `n`. Returns whether the ack was
    /// accepted; a rejected ack leaves the state untouched (spec:
    /// `ack?`, `ack?_rejects`).
    pub fn ack(&mut self, n: usize) -> bool {
        if self.cursor < n && n <= self.log.len() {
            self.cursor = n;
            true
        } else {
            false
        }
    }
}
