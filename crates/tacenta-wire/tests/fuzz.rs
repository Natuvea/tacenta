//! Malformed-input robustness for the wire codec. This codec is *proven* total
//! and panic-free in Lean (via Charon/Aeneas), so this is belt-and-suspenders:
//! it exercises the actual compiled Rust (the proof is about the translated
//! model) and guards against a regression the proof would also catch.

use tacenta_wire::{decode, decode_stream, encode, encode_stream};

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

fn fuzz<T>(decode: impl Fn(&[u8]) -> Option<T>, check: impl Fn(&T)) {
    let _ = decode(&[]);
    for a in 0u16..=255 {
        if let Some(v) = decode(&[a as u8]) {
            check(&v);
        }
        for b in 0u16..=255 {
            if let Some(v) = decode(&[a as u8, b as u8]) {
                check(&v);
            }
        }
    }
    let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50_000 {
        let input = rng.bytes(64);
        if let Some(v) = decode(&input) {
            check(&v);
        }
    }
}

#[test]
fn envelope_decoder_is_panic_free() {
    fuzz(decode, |v| {
        // `encode` is fallible (an over-long payload has no encoding), so guard.
        if let Some(bytes) = encode(v) {
            assert!(decode(&bytes).is_some());
        }
    });
}

#[test]
fn stream_decoder_is_panic_free() {
    fuzz(decode_stream, |v| {
        if let Some(bytes) = encode_stream(v) {
            assert!(decode_stream(&bytes).is_some());
        }
    });
    // `decode_one` (which `decode_stream` calls internally) is exercised
    // through the stream sweep above; it is not fuzzed directly because its
    // return borrows the input, which the generic helper cannot express.
}
