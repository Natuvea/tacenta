//! Malformed-input robustness for the directory protocol: no byte string makes
//! a decoder panic, and any value that decodes re-encodes to bytes that decode
//! again. Exhaustive over short inputs, random over longer ones, deterministic.

use tacenta_directory::{
    decode_dir_request, decode_dir_response, encode_dir_request, encode_dir_response,
};

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
fn dir_request_decoder_is_panic_free() {
    fuzz(decode_dir_request, |v| {
        assert!(decode_dir_request(&encode_dir_request(v)).is_some());
    });
}

#[test]
fn dir_response_decoder_is_panic_free() {
    fuzz(decode_dir_response, |v| {
        assert!(decode_dir_response(&encode_dir_response(v)).is_some());
    });
}
