//! Sortable, prefixed identifiers.
//!
//! An identifier is `"<prefix>_<ulid>"`: a type prefix (so the id names its
//! kind and is greppable) followed by a ULID — a 48-bit millisecond timestamp
//! then 80 bits of randomness, Crockford-base32 encoded to 26 characters.
//! Because the timestamp is in the high bits and the alphabet is order-
//! preserving, ids sort lexicographically by creation time.
//!
//! This is for **identifiers** only. Secrets (API keys, session tokens) keep a
//! prefix plus full random entropy (`random_token`) and are deliberately not
//! sortable — a sortable secret would leak its creation time and trade entropy
//! for order (decision record 0038).

use std::time::{SystemTime, UNIX_EPOCH};

use rand::{RngCore as _, TryRngCore as _};

/// Crockford base32 — no I, L, O, U; ascending byte values, so encoding
/// preserves order (string comparison matches numeric comparison).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A prefixed, sortable identifier: `"<prefix>_<ulid>"`.
pub fn prefixed(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut random = [0u8; 10];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut random);
    format!("{prefix}_{}", ulid(ms, &random))
}

/// Encode a 48-bit millisecond timestamp and 80 bits of randomness as a
/// 26-character Crockford-base32 ULID.
fn ulid(ms: u64, random: &[u8; 10]) -> String {
    // 128 bits: the low 48 bits of `ms`, then the 80 random bits.
    let mut bytes = [0u8; 16];
    bytes[0..6].copy_from_slice(&(ms & 0xFFFF_FFFF_FFFF).to_be_bytes()[2..8]);
    bytes[6..16].copy_from_slice(random);

    // Base32 from the top: 26 chars × 5 bits spans the 128-bit value (with two
    // high padding bits), so the timestamp lands in the leading characters.
    let mut value = u128::from_be_bytes(bytes);
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(value & 0x1F) as usize];
        value >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("crockford alphabet is ascii")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefixed_id_is_the_prefix_and_a_26_char_ulid() {
        let id = prefixed("ten");
        let (prefix, body) = id.split_once('_').unwrap();
        assert_eq!(prefix, "ten");
        assert_eq!(body.len(), 26);
        assert!(body.bytes().all(|b| CROCKFORD.contains(&b)));
    }

    #[test]
    fn ids_sort_by_timestamp() {
        // A later timestamp encodes to a lexicographically greater ulid, even
        // when its random tail is all zeros against the earlier one's all ones.
        let early = ulid(1_000, &[0xFF; 10]);
        let late = ulid(2_000, &[0x00; 10]);
        assert!(early < late, "{early} should sort before {late}");
    }

    #[test]
    fn same_timestamp_orders_by_randomness() {
        let lo = ulid(1_000, &[0x00; 10]);
        let hi = ulid(1_000, &[0xFF; 10]);
        assert!(lo < hi);
    }
}
