//! Multi-device user state. Mirrors `Tacenta.User` in the spec.
//!
//! One `User` holds a single append-only log shared by all of the
//! user's devices, and one acknowledgment cursor per device. Delivery
//! is per-device (`device_pending`); a message counts as delivered to
//! the user only when every device's cursor has passed it
//! (`delivered`, the minimum cursor). A newly linked device starts at
//! the log tail — no history backfill (decision record 0005).
//!
//! Invariant (spec: `User.valid`): every cursor is at most `log.len()`
//! — upheld because `append` only grows the log, `link_device` starts
//! at the current tail, and `ack` bounds-checks before moving a cursor.

/// Multi-device delivery state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct User<T> {
    log: Vec<T>,
    cursors: Vec<usize>,
}

impl<T> User<T> {
    /// A fresh user with no devices and no history.
    pub fn new() -> User<T> {
        User {
            log: Vec::new(),
            cursors: Vec::new(),
        }
    }

    /// The shared append-only log.
    pub fn log(&self) -> &[T] {
        &self.log
    }

    /// Per-device cursors, indexed by device id.
    pub fn cursors(&self) -> &[usize] {
        &self.cursors
    }

    /// Messages not yet acknowledged by device `d`, oldest first. An
    /// unknown device has nothing pending (spec: `devicePending` via
    /// `cursorOf`).
    pub fn device_pending(&self, d: usize) -> &[T] {
        // Indexing rather than `get`: matching on `Option<&usize>` is
        // outside what the translation handles.
        let cursor = if d < self.cursors.len() {
            self.cursors[d]
        } else {
            self.log.len()
        };
        &self.log[cursor..]
    }

    /// How many leading messages every device has acknowledged: the
    /// user-level delivery count. With no devices this is the whole
    /// log, vacuously (spec: `delivered`).
    pub fn delivered(&self) -> usize {
        // A manual loop rather than `Iterator::fold`: iterator adapters
        // translate as opaque axioms, and this function is proven.
        let mut m = self.log.len();
        let mut i = 0;
        while i < self.cursors.len() {
            let c = self.cursors[i];
            if c < m {
                m = c;
            }
            i += 1;
        }
        m
    }

    /// Append a message to the shared log. Always allowed; touches no
    /// cursor (spec: `append`).
    pub fn append(&mut self, e: T) {
        self.log.push(e);
    }

    /// Link a new device, starting at the log tail. Returns its device
    /// id (spec: `linkDevice`).
    pub fn link_device(&mut self) -> usize {
        self.cursors.push(self.log.len());
        self.cursors.len() - 1
    }

    /// Device `d` acknowledges everything up to `n`. Returns whether
    /// the ack was accepted; a rejected ack leaves the state untouched
    /// (spec: `ack?`).
    pub fn ack(&mut self, d: usize, n: usize) -> bool {
        // Indexed read + indexed write rather than `get_mut`: the
        // `Vec::index`/`index_mut` paths have refinement specs upstream
        // while the `get_mut` write-back does not. The `&&` short-circuit makes
        // both indexings provably in-bounds.
        if d < self.cursors.len() && self.cursors[d] < n && n <= self.log.len() {
            self.cursors[d] = n;
            true
        } else {
            false
        }
    }
}
