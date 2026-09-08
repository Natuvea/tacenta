//! A directory of public key material.
//!
//! Devices register their public identity key and prekey bundle here so
//! others can find them: a client looks up a peer's bundle to open an
//! encrypted session, and the server looks up a device's identity key to
//! authenticate its connection. Everything stored is *public* — no
//! secrets, no message contents, no cryptography in this crate. It holds
//! opaque blobs (the client does the serialization and the crypto), so,
//! like the relay, it never touches a private key or a plaintext.
//!
//! In-memory at runtime; `snapshot`/`restore` persist it, and
//! `tacenta-transport` serves it over the network.
//!
//! Registration trust here is *trust on first use*: the first registration
//! of a device address binds it to an identity key, and that binding is
//! sticky — a later registration must present the same identity key (it
//! may refresh the prekey bundle) or it is rejected. So an address cannot
//! be silently reassigned to a different identity, and a live registration
//! cannot be hijacked by a third party. This is the crypto-free half of
//! the trust model (a byte comparison); the other half — proving the
//! registrant holds the private key for the identity it submits — is
//! cryptographic and belongs to the caller admitting the registration
//! (decision record 0019). Authorized identity *rotation* (replacing the
//! bound key, signed by the old one) is offered through [`Directory::rotate`].

use std::collections::{HashMap, VecDeque};
use tacenta_relay::DeviceAddr;

mod persist;
mod protocol;
mod registration_limit;
pub use protocol::{
    DirRequest, DirResponse, decode_dir_request, decode_dir_response, encode_dir_request,
    encode_dir_response,
};
pub use registration_limit::{DEFAULT_MAX_PER_WINDOW, RegistrationLimiter};

// The trust-on-first-use registration decision and the rotation decision live
// in the leaf `tacenta-directory-core` crate as pure functions of one device's
// current binding — the part a Charon/Aeneas refinement translates and proves.
// `Directory` below is the container glue around them. `Registration` /
// `Rotation` are re-exported so this crate's public API is unchanged.
pub use tacenta_directory_core::{Registration, Rotation, register_core, rotate_core};

/// The outcome of setting a device's recovery key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deposit {
    /// The bundles were added to the device's pool; the count is the pool's
    /// new depth.
    Deposited(usize),
    /// The presented identity is not the one bound to this address, so the
    /// deposit was refused. Anyone may *fetch* a bundle; only the device may
    /// stock the pool it is served from.
    Rejected,
    /// The address is not registered, so there is no pool to stock.
    Unregistered,
}

/// What a dispensing lookup returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoverySet {
    /// The recovery key was stored (or replaced).
    Set,
    /// The address is not registered — no binding to attach recovery to.
    Unregistered,
}

/// A device's published public material: its identity key, its current
/// prekey bundle, and a pool of one-time bundles, all as the opaque bytes
/// the client produced.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct Entry {
    identity: Vec<u8>,
    /// Served when the pool is empty. Carries no one-time prekey, which is
    /// sound: the signed prekey and the KEM prekey are multi-use by design
    /// (decision 0050).
    bundle: Vec<u8>,
    /// Complete bundles, each carrying a distinct one-time prekey, each
    /// served at most once (decision 0074).
    ///
    /// **A pool of whole bundles rather than of bare prekeys**, which is a
    /// refinement of what 0074 wrote and the record says why: splicing a
    /// prekey into a stored bundle would make the directory parse and rebuild
    /// a cryptographic blob, and it holds opaque bytes precisely so it cannot
    /// (decision 0018). Whole bundles keep it from ever looking inside, work
    /// for whatever the provider publishes, and dispense the one-time curve prekey
    /// and the one-time KEM prekey together, which is what open-tacenta needs
    /// and a bare-prekey pool would have had to special-case.
    pool: VecDeque<Vec<u8>>,
}

/// The directory: a lookup from device to its published material, a
/// per-user index of devices (for multi-device fan-out), and an optional
/// per-device recovery key. The recovery key is stored separately from the
/// entry because it is orthogonal — set and used rarely, and not every
/// device has one — so `register` / `rotate` need not carry it.
#[derive(Debug, Default)]
pub struct Directory {
    entries: HashMap<DeviceAddr, Entry>,
    devices: HashMap<String, Vec<u32>>,
    recovery: HashMap<DeviceAddr, Vec<u8>>,
    /// The highest persisted-state generation the directory has witnessed for
    /// each device — the anti-rollback anchor of decision 0078.
    ///
    /// **Stored here, apart from the `Entry`, on purpose.** `register` rebuilds
    /// the entry on every refresh (a reconnecting client refreshes), which would
    /// reset a generation held inside it to zero and blind the rollback check
    /// exactly when a client reconnects. The generation is orthogonal to the
    /// identity binding — the same reason `recovery` lives apart — so it lives
    /// apart too, untouched by `register`, and only [`Directory::witness`]
    /// reads or advances it. Monotone: it never decreases.
    generations: HashMap<DeviceAddr, u64>,
}

/// The verdict of witnessing a device's presented persisted-state generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Witness {
    /// At or ahead of the highest generation seen. The state is current;
    /// resume normally.
    Fresh,
    /// Below the highest generation already seen for this device: an older
    /// state is being presented. Decision 0078's rollback signal — the client
    /// keeps its identity and discards its sessions rather than resuming a
    /// ratchet from a rewound point.
    RolledBack,
    /// No binding exists to witness against. A client witnesses only after
    /// registering, so this is a misuse or an unknown device rather than a
    /// normal outcome.
    Unregistered,
}

/// The rollback decision, as a pure function of the highest generation stored
/// and the one offered. Fresh iff the offer does not go backwards; the returned
/// `u64` is the new highest, which never decreases.
///
/// **Tested, not yet Lean-refined.** `register_core`/`rotate_core` live in
/// `tacenta-directory-core` and are mechanically refined to the spec. This rule
/// belongs there too and should move once it carries a matching Lean lemma;
/// until then it is a monotone-max the tests pin, kept in the glue crate so it
/// does not perturb the refined core's translation. (`docs/decisions/0078`.)
fn witness_core(stored: Option<u64>, offered: u64) -> (Witness, u64) {
    match stored {
        None => (Witness::Fresh, offered),
        Some(highest) if offered >= highest => (Witness::Fresh, offered),
        Some(highest) => (Witness::RolledBack, highest),
    }
}

impl Directory {
    pub fn new() -> Directory {
        Directory::default()
    }

    /// Publish a device's identity key and prekey bundle (both opaque
    /// bytes), under trust on first use. The first registration of an
    /// address binds it to `identity` and returns `Registered`. A later
    /// registration presenting the same `identity` refreshes the bundle
    /// and returns `Refreshed`; one presenting a different `identity`
    /// changes nothing and returns `Rejected`.
    /// Whether this device already has a binding. Used by the registration
    /// throttle (0079) to tell a *new* handle from a re-confirm: only a new
    /// binding is rate-limited, so a returning client is never throttled out of
    /// its own handle.
    pub fn contains_device(&self, device: &DeviceAddr) -> bool {
        self.entries.contains_key(device)
    }

    pub fn register(
        &mut self,
        device: &DeviceAddr,
        identity: Vec<u8>,
        bundle: Vec<u8>,
    ) -> Registration {
        let current = self.entries.get(device).map(|e| e.identity.clone());
        let (outcome, binding) = register_core(current, identity);
        match outcome {
            // Trust on first use rejected the change; `binding` is the
            // unchanged existing key, so there is nothing to store.
            Registration::Rejected => Registration::Rejected,
            // Refresh: same key, new bundle — replace the entry, leave the
            // device index alone (the device is already indexed).
            Registration::Refreshed => {
                self.entries.insert(
                    device.clone(),
                    Entry {
                        identity: binding,
                        bundle,
                        // A new bundle carries a new signed prekey, so every
                        // pooled bundle built against the old one is stale.
                        // Replacing rather than keeping is decision 0074's
                        // rotation rule.
                        pool: VecDeque::new(),
                    },
                );
                Registration::Refreshed
            }
            // Fresh registration: index the new device, then store the entry.
            Registration::Registered => {
                let list = self.devices.entry(device.user.clone()).or_default();
                if !list.contains(&device.device) {
                    list.push(device.device);
                    list.sort_unstable();
                }
                self.entries.insert(
                    device.clone(),
                    Entry {
                        identity: binding,
                        bundle,
                        // A new bundle carries a new signed prekey, so every
                        // pooled bundle built against the old one is stale.
                        // Replacing rather than keeping is decision 0074's
                        // rotation rule.
                        pool: VecDeque::new(),
                    },
                );
                Registration::Registered
            }
        }
    }

    /// Replace the identity key and prekey bundle bound to `device` — the
    /// authorized-rotation path, as opposed to `register`'s trust on first
    /// use. The caller must have verified that the change is authorized by
    /// the *currently bound* key before calling (key continuity), exactly
    /// as it verifies possession before `register`; the directory performs
    /// only the crypto-free replacement, and only for an address that is
    /// already bound. Rotating an unregistered address changes nothing.
    pub fn rotate(
        &mut self,
        device: &DeviceAddr,
        new_identity: Vec<u8>,
        new_bundle: Vec<u8>,
    ) -> Rotation {
        let current = self.entries.get(device).map(|e| e.identity.clone());
        let (outcome, binding) = rotate_core(current, new_identity);
        match (outcome, binding) {
            (Rotation::Rotated, Some(identity)) => {
                self.entries.insert(
                    device.clone(),
                    Entry {
                        identity,
                        bundle: new_bundle,
                        // Rotation replaces the identity as well as the
                        // bundle, so the pool is doubly stale.
                        pool: VecDeque::new(),
                    },
                );
                // Rotation is a fresh trust epoch, so the rollback anchor
                // resets. Without this, a generation anchor an attacker poisoned
                // to u64::MAX under the old key would outlive the rotation and
                // keep the recovered device rolled back on every reconnect —
                // rotation is the recovery path from that poisoning, and it must
                // actually recover.
                self.generations.remove(device);
                Rotation::Rotated
            }
            // Unregistered: no binding to replace, nothing stored.
            _ => Rotation::Unregistered,
        }
    }

    /// Attach (or replace) a recovery key for `device` — a key whose private
    /// half the owner keeps offline, so it survives the loss of the identity
    /// key. The caller must have verified that this is authorized by the
    /// *currently bound* identity key (as for `rotate`); the directory only
    /// stores the bytes, and only for an address that is already bound.
    /// Recovery then goes through `rotate`, authorized by this key.
    pub fn set_recovery(&mut self, device: &DeviceAddr, key: Vec<u8>) -> RecoverySet {
        if !self.entries.contains_key(device) {
            return RecoverySet::Unregistered;
        }
        self.recovery.insert(device.clone(), key);
        RecoverySet::Set
    }

    /// A device's recovery key bytes, if one is set. The admitting server
    /// verifies a recovery authorization against this before rotating.
    pub fn recovery_key(&self, device: &DeviceAddr) -> Option<&[u8]> {
        self.recovery.get(device).map(Vec::as_slice)
    }

    /// A device's public identity key bytes, for authenticating its
    /// connection. `None` if the device is not registered.
    pub fn identity(&self, device: &DeviceAddr) -> Option<&[u8]> {
        self.entries.get(device).map(|e| e.identity.as_slice())
    }

    /// Witness a device's presented persisted-state `generation`, the
    /// anti-rollback anchor of decision 0078.
    ///
    /// Records the highest generation seen for the device and reports whether
    /// this one goes backwards. The stored value only ever increases, so a
    /// later, genuine state advances it and an older, replayed state is caught
    /// as [`Witness::RolledBack`]. Possession of the device's identity key is
    /// proven at the transport before this is reached — the same gate `register`
    /// sits behind — so only the device that owns the binding can advance its
    /// own anchor.
    ///
    /// Only a registered device can be witnessed; an unknown one returns
    /// [`Witness::Unregistered`], which also bounds this map to devices that
    /// exist rather than to anything an unauthenticated caller names.
    pub fn witness(&mut self, device: &DeviceAddr, generation: u64) -> Witness {
        if !self.entries.contains_key(device) {
            return Witness::Unregistered;
        }
        let (verdict, highest) = witness_core(self.generations.get(device).copied(), generation);
        self.generations.insert(device.clone(), highest);
        verdict
    }

    /// The highest generation witnessed for a device. Test-only: snapshotting
    /// iterates the map directly, and no shipping path reads a single device's
    /// anchor back.
    #[cfg(test)]
    pub(crate) fn generation(&self, device: &DeviceAddr) -> Option<u64> {
        self.generations.get(device).copied()
    }

    /// Restore a witnessed generation on load, without the monotone check —
    /// the snapshot is trusted, and this is the value the check will run
    /// against next.
    pub(crate) fn restore_generation(&mut self, device: &DeviceAddr, generation: u64) {
        self.generations.insert(device.clone(), generation);
    }

    /// Stock a device's one-time bundle pool (decision 0074).
    ///
    /// Each entry is a complete bundle carrying a one-time prekey that no
    /// other entry carries, produced by the device itself. `identity` must be
    /// the key currently bound to the address: anyone may *fetch* a bundle,
    /// but only the device may stock the pool it is served from, or a third
    /// party could feed prekeys it holds the private halves of.
    ///
    /// Appends rather than replaces, so a device can top up without knowing
    /// how much of its last batch has been dispensed.
    pub fn deposit_prekeys(
        &mut self,
        device: &DeviceAddr,
        identity: &[u8],
        bundles: Vec<Vec<u8>>,
    ) -> Deposit {
        let Some(entry) = self.entries.get_mut(device) else {
            return Deposit::Unregistered;
        };
        if entry.identity != identity {
            return Deposit::Rejected;
        }
        entry.pool.extend(bundles);
        Deposit::Deposited(entry.pool.len())
    }

    /// How many one-time bundles remain for `device`. What a client polls to
    /// decide whether to replenish, and what a test asserts on.
    pub fn pool_depth(&self, device: &DeviceAddr) -> usize {
        self.entries.get(device).map_or(0, |e| e.pool.len())
    }

    /// Take a bundle for a peer opening a session, consuming a one-time
    /// bundle if one remains (decision 0074).
    ///
    /// **This is the dispensing lookup, and the only one a peer should get.**
    /// It removes what it returns, so two callers cannot be handed the same
    /// one-time prekey. When the pool is empty it falls back to the stored
    /// multi-use bundle, which is sound rather than an error: the signed
    /// prekey and the KEM prekey are multi-use by design (decision 0050), and
    /// only the extra forward secrecy of a one-time key is lost.
    ///
    /// **The atomicity is the substance of 0074**, and here it is structural:
    /// `&mut self` means the borrow checker will not let a read and a write
    /// straddle anything, and the server holds the directory behind a mutex,
    /// so the pop is indivisible. A read-then-write dispenser would serve
    /// duplicates under concurrency, which is what this rules out on the
    /// server's side rather than the client's.
    pub fn take_bundle(&mut self, device: &DeviceAddr) -> Option<Vec<u8>> {
        let entry = self.entries.get_mut(device)?;
        Some(match entry.pool.pop_front() {
            Some(one_time) => one_time,
            None => entry.bundle.clone(),
        })
    }

    /// A device's published prekey bundle bytes **without dispensing**.
    ///
    /// The multi-use fallback as stored, for callers that need to see what is
    /// published without consuming anything: persistence, diagnostics, tests.
    /// A peer opening a session wants [`take_bundle`] instead; this one hands
    /// the same bytes to everybody, which is what decision 0074 exists to stop
    /// happening on the session path. `None` if the device is not registered.
    pub fn bundle(&self, device: &DeviceAddr) -> Option<&[u8]> {
        self.entries.get(device).map(|e| e.bundle.as_slice())
    }

    /// The device ids registered for a user, sorted. Empty for an unknown user.
    ///
    /// **Nothing calls this yet.** The client's `send` takes a single
    /// `DeviceAddr`, so a message reaches the one device the caller named and
    /// no other. The index is here; the fan-out is future work.
    pub fn devices_of(&self, user: &str) -> &[u32] {
        self.devices.get(user).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_witness_is_monotone_and_catches_a_rollback() {
        let bob = DeviceAddr::new("+bob", 1);
        let mut dir = Directory::new();

        // An unregistered device cannot be witnessed.
        assert_eq!(dir.witness(&bob, 5), Witness::Unregistered);

        dir.register(&bob, b"bob-id".to_vec(), b"bundle".to_vec());

        // First witness sets the anchor; equal and higher stay fresh.
        assert_eq!(dir.witness(&bob, 5), Witness::Fresh);
        assert_eq!(dir.witness(&bob, 5), Witness::Fresh);
        assert_eq!(dir.witness(&bob, 7), Witness::Fresh);

        // A lower generation is a rollback, and the anchor does not drop.
        assert_eq!(dir.witness(&bob, 6), Witness::RolledBack);
        assert_eq!(dir.generation(&bob), Some(7), "the anchor never decreases");
        // ...so even after the rollback attempt, 7 is still the floor.
        assert_eq!(dir.witness(&bob, 6), Witness::RolledBack);
        assert_eq!(dir.witness(&bob, 8), Witness::Fresh);
    }

    #[test]
    fn a_refresh_does_not_reset_the_witnessed_generation() {
        // A reconnecting client refreshes its registration; the anchor must
        // survive that, or a rollback would go undetected right after reconnect.
        let bob = DeviceAddr::new("+bob", 1);
        let mut dir = Directory::new();
        dir.register(&bob, b"bob-id".to_vec(), b"bundle".to_vec());
        assert_eq!(dir.witness(&bob, 9), Witness::Fresh);

        // Refresh (same identity, new bundle) rebuilds the Entry.
        assert_eq!(
            dir.register(&bob, b"bob-id".to_vec(), b"newer-bundle".to_vec()),
            Registration::Refreshed
        );

        // The anchor is intact: an old generation is still a rollback.
        assert_eq!(dir.generation(&bob), Some(9));
        assert_eq!(dir.witness(&bob, 4), Witness::RolledBack);
    }

    #[test]
    fn rotation_resets_the_witnessed_generation() {
        // A rotation is a fresh trust epoch: the anchor must reset, or a
        // poisoned one (say u64::MAX) would outlive the rotation and keep a
        // recovered device permanently rolled back.
        let bob = DeviceAddr::new("+bob", 1);
        let mut dir = Directory::new();
        dir.register(&bob, b"old-id".to_vec(), b"bundle".to_vec());
        assert_eq!(dir.witness(&bob, u64::MAX), Witness::Fresh); // anchor poisoned
        assert_eq!(dir.witness(&bob, 1), Witness::RolledBack);

        // Rotate to a new key: the anchor is cleared.
        assert_eq!(
            dir.rotate(&bob, b"new-id".to_vec(), b"new-bundle".to_vec()),
            Rotation::Rotated
        );
        assert_eq!(dir.generation(&bob), None, "the anchor resets on rotation");
        // The recovered device witnesses from scratch again.
        assert_eq!(dir.witness(&bob, 1), Witness::Fresh);
    }

    #[test]
    fn register_and_look_up() {
        let mut dir = Directory::new();
        let bob1 = DeviceAddr::new("+bob", 1);
        let bob2 = DeviceAddr::new("+bob", 2);

        assert_eq!(
            dir.register(&bob1, b"bob1-identity".to_vec(), b"bob1-bundle".to_vec()),
            Registration::Registered
        );
        assert_eq!(
            dir.register(&bob2, b"bob2-identity".to_vec(), b"bob2-bundle".to_vec()),
            Registration::Registered
        );

        assert_eq!(dir.identity(&bob1), Some(&b"bob1-identity"[..]));
        assert_eq!(dir.bundle(&bob2), Some(&b"bob2-bundle"[..]));
        assert_eq!(dir.devices_of("+bob"), &[1, 2]);

        // Unknown lookups.
        assert_eq!(dir.identity(&DeviceAddr::new("+nobody", 1)), None);
        assert_eq!(dir.devices_of("+nobody"), &[] as &[u32]);
    }

    #[test]
    fn same_identity_refreshes_the_bundle() {
        let mut dir = Directory::new();
        let bob1 = DeviceAddr::new("+bob", 1);
        dir.register(&bob1, b"bob-identity".to_vec(), b"old-bundle".to_vec());

        // A re-registration under the same identity key refreshes the
        // bundle and does not duplicate the device.
        assert_eq!(
            dir.register(&bob1, b"bob-identity".to_vec(), b"new-bundle".to_vec()),
            Registration::Refreshed
        );
        assert_eq!(dir.bundle(&bob1), Some(&b"new-bundle"[..]));
        assert_eq!(dir.devices_of("+bob"), &[1]);
    }

    #[test]
    fn a_different_identity_cannot_take_a_bound_address() {
        let mut dir = Directory::new();
        let bob1 = DeviceAddr::new("+bob", 1);
        dir.register(&bob1, b"bob-identity".to_vec(), b"bob-bundle".to_vec());

        // Trust on first use: the address is bound to Bob's identity, so a
        // registration presenting a different identity key is rejected and
        // nothing changes.
        assert_eq!(
            dir.register(
                &bob1,
                b"mallory-identity".to_vec(),
                b"mallory-bundle".to_vec()
            ),
            Registration::Rejected
        );
        assert_eq!(dir.identity(&bob1), Some(&b"bob-identity"[..]));
        assert_eq!(dir.bundle(&bob1), Some(&b"bob-bundle"[..]));
    }

    #[test]
    fn rotate_replaces_a_bound_identity() {
        let mut dir = Directory::new();
        let bob1 = DeviceAddr::new("+bob", 1);

        // Rotating an unregistered address does nothing.
        assert_eq!(
            dir.rotate(&bob1, b"new-id".to_vec(), b"new-bundle".to_vec()),
            Rotation::Unregistered
        );
        assert_eq!(dir.identity(&bob1), None);

        // Once bound, rotation replaces the identity key and bundle without
        // disturbing the device index.
        dir.register(&bob1, b"old-id".to_vec(), b"old-bundle".to_vec());
        assert_eq!(
            dir.rotate(&bob1, b"new-id".to_vec(), b"new-bundle".to_vec()),
            Rotation::Rotated
        );
        assert_eq!(dir.identity(&bob1), Some(&b"new-id"[..]));
        assert_eq!(dir.bundle(&bob1), Some(&b"new-bundle"[..]));
        assert_eq!(dir.devices_of("+bob"), &[1]);

        // After rotation the new identity is the bound one: trust on first
        // use now protects it, and re-presenting the old identity via
        // register is rejected.
        assert_eq!(
            dir.register(&bob1, b"old-id".to_vec(), b"old-bundle".to_vec()),
            Registration::Rejected
        );
    }
}

#[cfg(test)]
mod dispensing_tests {
    use super::*;

    fn addr(user: &str, device: u32) -> DeviceAddr {
        DeviceAddr::new(user, device)
    }

    /// The property the whole of decision 0074 exists for: a one-time bundle
    /// is served to at most one peer.
    #[test]
    fn each_one_time_bundle_is_served_once() {
        let mut dir = Directory::new();
        let bob = addr("+bob", 1);
        dir.register(&bob, b"bob-id".to_vec(), b"fallback".to_vec());
        dir.deposit_prekeys(
            &bob,
            b"bob-id",
            vec![b"otp-1".to_vec(), b"otp-2".to_vec(), b"otp-3".to_vec()],
        );

        let served: Vec<Vec<u8>> = (0..3).filter_map(|_| dir.take_bundle(&bob)).collect();
        let mut sorted = served.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "a one-time bundle was served twice");
        assert_eq!(dir.pool_depth(&bob), 0);

        // Exhaustion is a fallback, not an error.
        assert_eq!(dir.take_bundle(&bob), Some(b"fallback".to_vec()));
        assert_eq!(dir.take_bundle(&bob), Some(b"fallback".to_vec()));
    }

    /// Only the bound device may stock the pool it is served from. Otherwise a
    /// third party could feed prekeys whose private halves it holds.
    #[test]
    fn only_the_bound_identity_may_deposit() {
        let mut dir = Directory::new();
        let bob = addr("+bob", 1);
        dir.register(&bob, b"bob-id".to_vec(), b"fallback".to_vec());

        assert_eq!(
            dir.deposit_prekeys(&bob, b"mallory-id", vec![b"evil".to_vec()]),
            Deposit::Rejected
        );
        assert_eq!(dir.pool_depth(&bob), 0);
        assert_eq!(
            dir.deposit_prekeys(&addr("+nobody", 1), b"any", vec![b"x".to_vec()]),
            Deposit::Unregistered
        );
        assert_eq!(
            dir.deposit_prekeys(&bob, b"bob-id", vec![b"good".to_vec()]),
            Deposit::Deposited(1)
        );
    }

    /// A new bundle carries a new signed prekey, so bundles pooled against the
    /// old one are stale and must not be served.
    #[test]
    fn republishing_and_rotating_clear_the_pool() {
        let mut dir = Directory::new();
        let bob = addr("+bob", 1);
        dir.register(&bob, b"bob-id".to_vec(), b"fallback".to_vec());
        dir.deposit_prekeys(&bob, b"bob-id", vec![b"otp".to_vec()]);
        assert_eq!(dir.pool_depth(&bob), 1);

        dir.register(&bob, b"bob-id".to_vec(), b"fresher".to_vec());
        assert_eq!(dir.pool_depth(&bob), 0, "a refresh kept a stale pool");

        dir.deposit_prekeys(&bob, b"bob-id", vec![b"otp".to_vec()]);
        dir.rotate(&bob, b"bob-id-2".to_vec(), b"rotated".to_vec());
        assert_eq!(dir.pool_depth(&bob), 0, "a rotation kept a stale pool");
    }

    /// Concurrent lookups through the mutex the server actually uses. A
    /// dispenser that is correct single-threaded and duplicates under load has
    /// fixed nothing, which is why this test exists rather than a comment
    /// saying the pop is atomic.
    #[test]
    fn concurrent_lookups_never_serve_the_same_bundle_twice() {
        use std::sync::{Arc, Mutex};

        const POOL: usize = 200;
        const THREADS: usize = 8;

        let mut dir = Directory::new();
        let bob = addr("+bob", 1);
        dir.register(&bob, b"bob-id".to_vec(), b"fallback".to_vec());
        dir.deposit_prekeys(
            &bob,
            b"bob-id",
            (0..POOL).map(|i| format!("otp-{i}").into_bytes()).collect(),
        );

        let dir = Arc::new(Mutex::new(dir));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let dir = Arc::clone(&dir);
                let bob = bob.clone();
                std::thread::spawn(move || {
                    let mut got = Vec::new();
                    for _ in 0..(POOL / THREADS) {
                        let b = dir.lock().expect("directory mutex").take_bundle(&bob);
                        got.push(b.expect("registered"));
                    }
                    got
                })
            })
            .collect();

        let mut all: Vec<Vec<u8>> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread panicked"))
            .collect();
        let total = all.len();
        all.sort();
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "a one-time bundle was served to two peers concurrently"
        );
        assert!(
            !all.contains(&b"fallback".to_vec()),
            "the pool should have covered every request"
        );
    }
}
