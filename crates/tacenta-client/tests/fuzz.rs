//! Malformed-input robustness for the client's hand-rolled parser: no byte
//! string makes `Contacts::from_bytes` panic, and any value that decodes
//! re-encodes to bytes that decode again. Exhaustive over short inputs, random
//! over longer ones, deterministic. (The session-state split parser is covered
//! by a unit test in the crate, and the provider's `import_sessions` by
//! tacenta-core's fuzz suite.)

use tacenta_client::Contacts;

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

#[test]
fn contacts_decoder_is_panic_free() {
    let check = |c: &Contacts| {
        // A decoded contact list re-encodes to bytes that decode again.
        assert!(Contacts::from_bytes(&c.to_bytes()).is_some());
    };

    let _ = Contacts::from_bytes(&[]);
    for a in 0u16..=255 {
        if let Some(c) = Contacts::from_bytes(&[a as u8]) {
            check(&c);
        }
        for b in 0u16..=255 {
            if let Some(c) = Contacts::from_bytes(&[a as u8, b as u8]) {
                check(&c);
            }
        }
    }
    let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50_000 {
        let input = rng.bytes(96);
        if let Some(c) = Contacts::from_bytes(&input) {
            check(&c);
        }
    }
}
