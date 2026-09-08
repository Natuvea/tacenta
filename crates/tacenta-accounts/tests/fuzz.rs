//! Malformed-input robustness for the account wire protocol: no byte string
//! makes a decoder panic, and any value that decodes re-encodes to bytes that
//! decode again. Exhaustive over inputs of length 0–2 (where truncation panics
//! hide) and random over longer ones, deterministic so the run is reproducible.
//! Only `tacenta-wire` is *proven* total; these decoders are hand-rolled, so
//! this is their panic-freedom evidence.

use tacenta_accounts::{
    AccountRequest, AccountResponse, decode_account_request, decode_account_response,
    encode_account_request, encode_account_response,
};

/// A tiny deterministic PRNG (an LCG), so a failure reproduces exactly.
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

/// Drive `decode` over exhaustive short inputs and many random longer ones. A
/// decoded value is passed to `check` (which asserts re-encode round-trips).
/// The test passing at all is the panic-freedom assertion.
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
fn account_request_decoder_is_panic_free() {
    fuzz(decode_account_request, |v: &AccountRequest| {
        assert!(decode_account_request(&encode_account_request(v)).is_some());
    });
}

#[test]
fn account_response_decoder_is_panic_free() {
    fuzz(decode_account_response, |v: &AccountResponse| {
        assert!(decode_account_response(&encode_account_response(v)).is_some());
    });
}
