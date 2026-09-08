//! Spec-conformance property tests for the directory trust rules.
//!
//! The trust-critical properties of `Directory::register` / `rotate` are
//! machine-checked in Lean (`spec/Tacenta/Directory.lean`): trust on first
//! use (`register_tofu`), framing (`register_frames`), and the rotation
//! outcomes (`rotate_requires_binding`, `rotate_rebinds`). Those proofs are
//! about the Lean *model* — an abstract `Device -> Option Identity`. This
//! file is the empirical bridge from that model to the shipped Rust: it runs
//! randomized operation traces against both the real `Directory` and a
//! reference model transliterated directly from the Lean spec, and asserts
//! they agree after every step. It also checks each named theorem pointwise.
//!
//! This does not *replace* a Charon/Aeneas refinement (the honest gap noted
//! in `docs/claims.md`) — a proof covers all inputs,
//! a test covers the ones it draws. But it turns "the Rust is written to
//! match the spec" from an assertion into mechanical, randomized evidence,
//! which is the standard to apply before trusting the gap.
//!
//! Deterministic (a fixed-seed LCG, no `proptest` dependency), matching the
//! `fuzz.rs` convention in this crate.

use std::collections::HashMap;
use tacenta_directory::{Directory, Registration, Rotation};
use tacenta_relay::DeviceAddr;

/// Deterministic linear-congruential generator (glibc constants). Same shape
/// as the crate's `fuzz.rs` — reproducible traces, no external crate.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The reference model: the Lean spec's `Directory := Device -> Option
/// Identity` (`spec/Tacenta/Directory.lean`), transliterated. It stores only
/// the identity binding — the trust-relevant state — deliberately ignoring
/// the prekey bundle and device index, exactly as the Lean model abstracts
/// them away. `register` and `rotate` reproduce the spec's `match` clauses.
#[derive(Default)]
struct SpecModel {
    binding: HashMap<DeviceAddr, Vec<u8>>,
}

impl SpecModel {
    /// The Lean `register`: `none => registered/bind`, `some existing =>
    /// existing == id ? refreshed : rejected`, binding unchanged either way
    /// unless fresh.
    fn register(&mut self, device: &DeviceAddr, identity: &[u8]) -> Registration {
        match self.binding.get(device) {
            None => {
                self.binding.insert(device.clone(), identity.to_vec());
                Registration::Registered
            }
            Some(existing) => {
                if existing.as_slice() == identity {
                    Registration::Refreshed
                } else {
                    Registration::Rejected
                }
            }
        }
    }

    /// The Lean `rotate`: `none => unregistered`, `some _ => rotated/bind`.
    fn rotate(&mut self, device: &DeviceAddr, new_identity: &[u8]) -> Rotation {
        match self.binding.get(device) {
            None => Rotation::Unregistered,
            Some(_) => {
                self.binding.insert(device.clone(), new_identity.to_vec());
                Rotation::Rotated
            }
        }
    }

    fn identity(&self, device: &DeviceAddr) -> Option<&[u8]> {
        self.binding.get(device).map(Vec::as_slice)
    }
}

/// A small, fixed device space so random traces revisit the same addresses
/// often enough to exercise re-registration, rejection, and rotation.
fn device_space() -> Vec<DeviceAddr> {
    let mut v = Vec::new();
    for user in ["+alice", "+bob", "+carol"] {
        for dev in 1u32..=2 {
            v.push(DeviceAddr::new(user, dev));
        }
    }
    v
}

/// A small identity-key space, so a re-registration lands on the same key
/// (refresh) or a different one (reject) with meaningful probability. The
/// `0xA0 | k` byte keeps each key distinct and obvious in a failure dump.
fn identity_space() -> Vec<Vec<u8>> {
    (0u8..4).map(|k| vec![0xA0 | k]).collect()
}

#[test]
fn rust_directory_refines_the_lean_spec_model() {
    let devices = device_space();
    let ids = identity_space();

    // Many independent traces from distinct seeds; each trace is a random
    // interleaving of register / rotate over the shared device/identity
    // space, run in lockstep against the Rust directory and the spec model.
    for seed in 0..2_000u64 {
        let mut rust = Directory::new();
        let mut spec = SpecModel::default();
        let mut rng = Lcg(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1));

        for _ in 0..40 {
            let device = &devices[rng.below(devices.len() as u64) as usize];
            let identity = &ids[rng.below(ids.len() as u64) as usize];

            match rng.below(2) {
                0 => {
                    let r_out = rust.register(device, identity.clone(), b"bundle".to_vec());
                    let s_out = spec.register(device, identity);
                    assert_eq!(
                        r_out, s_out,
                        "register outcome diverged at seed {seed}, device {device:?}"
                    );
                }
                _ => {
                    let r_out = rust.rotate(device, identity.clone(), b"bundle".to_vec());
                    let s_out = spec.rotate(device, identity);
                    assert_eq!(
                        r_out, s_out,
                        "rotate outcome diverged at seed {seed}, device {device:?}"
                    );
                }
            }

            // The binding state — the trust-relevant observable — must agree
            // for every device after every operation. This is the refinement
            // relation the Lean proofs are about, checked on the real Rust.
            for d in &devices {
                assert_eq!(
                    rust.identity(d),
                    spec.identity(d),
                    "identity binding diverged at seed {seed}, device {d:?}"
                );
            }
        }
    }
}

#[test]
fn register_tofu_holds_on_rust() {
    // `Directory.register_tofu`: whatever a device is bound to, `register`
    // leaves it bound to exactly that — a different identity cannot displace
    // an existing binding.
    let devices = device_space();
    let ids = identity_space();

    for seed in 0..2_000u64 {
        let mut rust = Directory::new();
        let mut rng = Lcg(seed.wrapping_mul(0x2545F4914F6CDD1D).wrapping_add(7));

        for _ in 0..40 {
            let device = &devices[rng.below(devices.len() as u64) as usize];
            let identity = ids[rng.below(ids.len() as u64) as usize].clone();

            let bound_before = rust.identity(device).map(<[u8]>::to_vec);
            let out = rust.register(device, identity.clone(), b"bundle".to_vec());

            match bound_before {
                Some(key) => {
                    // Already bound: the binding is unchanged regardless of
                    // the outcome (refreshed on same key, rejected on other).
                    assert_ne!(out, Registration::Registered);
                    assert_eq!(
                        rust.identity(device),
                        Some(key.as_slice()),
                        "TOFU violated: register displaced a binding at seed {seed}"
                    );
                }
                None => {
                    // Fresh: now bound to exactly the presented identity.
                    assert_eq!(out, Registration::Registered);
                    assert_eq!(rust.identity(device), Some(identity.as_slice()));
                }
            }
        }
    }
}

#[test]
fn register_and_rotate_frame_other_devices_on_rust() {
    // `Directory.register_frames` / the rotate analog: an operation on one
    // device never changes another device's binding.
    let devices = device_space();
    let ids = identity_space();

    for seed in 0..2_000u64 {
        let mut rust = Directory::new();
        let mut rng = Lcg(seed.wrapping_mul(0x94D049BB133111EB).wrapping_add(3));

        for _ in 0..40 {
            let target = &devices[rng.below(devices.len() as u64) as usize];
            let identity = ids[rng.below(ids.len() as u64) as usize].clone();

            let others: Vec<(DeviceAddr, Option<Vec<u8>>)> = devices
                .iter()
                .filter(|d| *d != target)
                .map(|d| (d.clone(), rust.identity(d).map(<[u8]>::to_vec)))
                .collect();

            if rng.below(2) == 0 {
                rust.register(target, identity, b"bundle".to_vec());
            } else {
                rust.rotate(target, identity, b"bundle".to_vec());
            }

            for (d, before) in others {
                assert_eq!(
                    rust.identity(&d).map(<[u8]>::to_vec),
                    before,
                    "framing violated: an op on {target:?} changed {d:?} at seed {seed}"
                );
            }
        }
    }
}

#[test]
fn rotate_outcomes_match_the_spec_on_rust() {
    // `Directory.rotate_requires_binding` (unbound -> Unregistered, no
    // change) and `rotate_rebinds` (bound -> Rotated, now the new key).
    let devices = device_space();
    let ids = identity_space();

    for seed in 0..2_000u64 {
        let mut rust = Directory::new();
        let mut rng = Lcg(seed.wrapping_mul(0xD1342543DE82EF95).wrapping_add(11));

        for _ in 0..40 {
            let device = &devices[rng.below(devices.len() as u64) as usize];
            let identity = ids[rng.below(ids.len() as u64) as usize].clone();

            let was_bound = rust.identity(device).is_some();
            let out = rust.rotate(device, identity.clone(), b"bundle".to_vec());

            if was_bound {
                assert_eq!(out, Rotation::Rotated);
                assert_eq!(
                    rust.identity(device),
                    Some(identity.as_slice()),
                    "rotate did not rebind at seed {seed}"
                );
            } else {
                assert_eq!(out, Rotation::Unregistered);
                assert_eq!(
                    rust.identity(device),
                    None,
                    "rotate bound an unregistered device at seed {seed}"
                );
            }

            // Re-seed the directory occasionally so later iterations hit the
            // bound case too.
            if !was_bound && rng.below(2) == 0 {
                rust.register(device, identity, b"bundle".to_vec());
            }
        }
    }
}
