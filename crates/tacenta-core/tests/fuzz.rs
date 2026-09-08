//! Malformed-input robustness for the hand-rolled parsers in `crypto`: no byte
//! string makes `DefaultProvider::from_identity` or `DefaultProvider::import_sessions` panic. The
//! prekey-bundle codec is covered in `integration_properties.rs`; this covers
//! the identity and session-state parsers (the latter added with client
//! session persistence, decision record 0051). Exhaustive over short inputs,
//! random over longer ones, deterministic.

use futures_util::FutureExt as _;
use rand::TryRngCore as _;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// A small deterministic PRNG, matching the other crates' fuzz harnesses.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Feed exhaustive short inputs and many random longer ones to `parse`,
/// asserting only that it never panics.
fn sweep(mut parse: impl FnMut(&[u8])) {
    parse(&[]);
    for a in 0u16..=255 {
        parse(&[a as u8]);
        for b in 0u16..=255 {
            parse(&[a as u8, b as u8]);
        }
    }
    let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50_000 {
        let input = rng.bytes(128);
        parse(&input);
    }
}

#[test]
fn from_identity_is_panic_free() {
    sweep(|input| {
        let _ = DefaultProvider::from_identity("+fuzz", 1, input);
    });
}

#[test]
fn import_sessions_is_panic_free() {
    // A real party to import into: its identity blob is valid, so
    // `import_sessions` reaches its own parser rather than failing at
    // construction. Reused across inputs; panic-freedom does not depend on the
    // accumulated store.
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let seed = DefaultProvider::generate("+fuzz", 1, &mut rng).unwrap();
    let identity = seed.export_identity();
    let mut party = DefaultProvider::from_identity("+fuzz", 1, &identity).unwrap();
    sweep(|input| {
        let _ = now(CryptoProvider::import_sessions(&mut party, input));
    });
}
