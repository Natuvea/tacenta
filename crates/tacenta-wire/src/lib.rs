//! Wire formats: envelope encoding, framing, and parsing.
//!
//! This crate is the verified zone. Everything here must stay inside the
//! Aeneas-friendly subset of Rust (no `unsafe`, no interior mutability,
//! panic-free), because it is translated to Lean and proved against the
//! specification in `spec/`. The layout implemented here is specified in
//! `spec/Tacenta/Wire.lean`, and the conformance vectors extracted from
//! that spec (`contracts/vectors/envelope-v1.json`) are this crate's
//! acceptance tests.

// The verified zone avoids the `?` operator: it desugars through the
// `Try` trait, which the Aeneas translation can only model as opaque
// axioms. `let`-`else` keeps the generated Lean fully definable, at the
// price of this lint.
#![allow(clippy::question_mark)]

/// Wire-format version tag carried by every envelope.
///
/// Must match `Tacenta.wireVersion` in `spec/Tacenta/Basic.lean`; the
/// conformance suite checks the two never drift.
pub const WIRE_VERSION: u16 = 1;

// Compile-time counterpart of `Tacenta.wireVersion_pos` in the spec.
// Named (not `const _`) so the Aeneas translation gets a legal Lean name.
#[allow(dead_code)]
const WIRE_VERSION_IS_POSITIVE: () = assert!(WIRE_VERSION > 0);

/// Fixed header size: version (2) + kind (1) + payload length (4).
const HEADER_LEN: usize = 7;

/// Envelope kinds carried on the wire. Mirrors `Tacenta.Wire.Kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dm,
    Group,
    Receipt,
}

impl Kind {
    pub fn to_byte(self) -> u8 {
        match self {
            Kind::Dm => 1,
            Kind::Group => 2,
            Kind::Receipt => 3,
        }
    }

    pub fn from_byte(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Dm),
            2 => Some(Kind::Group),
            3 => Some(Kind::Receipt),
            _ => None,
        }
    }
}

/// A v1 envelope. Mirrors `Tacenta.Wire.Envelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub payload: Vec<u8>,
}

/// Encode an envelope. `None` iff the payload cannot fit a u32 length.
///
/// Style note: `let`-`else` instead of `?` throughout this crate — the
/// `?` operator desugars through the `Try` trait, which the Aeneas
/// translation can only represent as opaque axioms; plain matches keep
/// the generated Lean fully definable and provable.
pub fn encode(e: &Envelope) -> Option<Vec<u8>> {
    let Ok(len) = u32::try_from(e.payload.len()) else {
        return None;
    };
    // saturating_add: the capacity is only an optimization, and a
    // checked add here would be the one panic path in the verified
    // zone (32-bit usize, near-u32::MAX payload).
    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(e.payload.len()));
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.push(e.kind.to_byte());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&e.payload);
    Some(out)
}

/// Decode an envelope, rejecting anything `encode` would not produce:
/// wrong version, unknown kind, a length field that disagrees with the
/// actual payload size, or trailing bytes.
pub fn decode(bytes: &[u8]) -> Option<Envelope> {
    let Some(version_slice) = bytes.get(0..2) else {
        return None;
    };
    let Ok(version) = <[u8; 2]>::try_from(version_slice) else {
        return None;
    };
    if u16::from_be_bytes(version) != WIRE_VERSION {
        return None;
    }
    let Some(&kind_byte) = bytes.get(2) else {
        return None;
    };
    let Some(kind) = Kind::from_byte(kind_byte) else {
        return None;
    };
    let Some(len_slice) = bytes.get(3..HEADER_LEN) else {
        return None;
    };
    let Ok(len_field) = <[u8; 4]>::try_from(len_slice) else {
        return None;
    };
    let Some(payload) = bytes.get(HEADER_LEN..) else {
        return None;
    };
    if payload.len() != u32::from_be_bytes(len_field) as usize {
        return None;
    }
    Some(Envelope {
        kind,
        payload: payload.to_vec(),
    })
}

/// Parse one envelope from the front of a buffer, returning it together
/// with the unconsumed remainder. Mirrors `Tacenta.Wire.decodeOne`:
/// like `decode` but tolerant of trailing bytes, which it returns.
pub fn decode_one(bytes: &[u8]) -> Option<(Envelope, &[u8])> {
    let Some(version_slice) = bytes.get(0..2) else {
        return None;
    };
    let Ok(version) = <[u8; 2]>::try_from(version_slice) else {
        return None;
    };
    if u16::from_be_bytes(version) != WIRE_VERSION {
        return None;
    }
    let Some(&kind_byte) = bytes.get(2) else {
        return None;
    };
    let Some(kind) = Kind::from_byte(kind_byte) else {
        return None;
    };
    let Some(len_slice) = bytes.get(3..HEADER_LEN) else {
        return None;
    };
    let Ok(len_field) = <[u8; 4]>::try_from(len_slice) else {
        return None;
    };
    let len = u32::from_be_bytes(len_field) as usize;
    let Some(after_header) = bytes.get(HEADER_LEN..) else {
        return None;
    };
    let Some(payload) = after_header.get(..len) else {
        return None;
    };
    let Some(rest) = after_header.get(len..) else {
        return None;
    };
    Some((
        Envelope {
            kind,
            payload: payload.to_vec(),
        },
        rest,
    ))
}

/// Encode a sequence of envelopes into one buffer (concatenation).
/// `None` if any envelope is too large to encode. Mirrors
/// `Tacenta.Wire.encodeStream`.
pub fn encode_stream(envelopes: &[Envelope]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < envelopes.len() {
        let Some(b) = encode(&envelopes[i]) else {
            return None;
        };
        out.extend_from_slice(&b);
        i += 1;
    }
    Some(out)
}

/// Decode a whole stream: repeatedly parse one envelope until the buffer
/// is empty. `None` if any parse fails or the bytes do not divide
/// cleanly into envelopes. Mirrors `Tacenta.Wire.decodeStream`.
pub fn decode_stream(bytes: &[u8]) -> Option<Vec<Envelope>> {
    let mut out = Vec::new();
    let mut buf = bytes;
    while !buf.is_empty() {
        let Some((e, rest)) = decode_one(buf) else {
            return None;
        };
        out.push(e);
        buf = rest;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex string");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    fn kind_by_name(name: &str) -> Kind {
        match name {
            "dm" => Kind::Dm,
            "group" => Kind::Group,
            "receipt" => Kind::Receipt,
            other => panic!("unknown kind in vectors: {other}"),
        }
    }

    /// Every vector extracted from the Lean spec must encode and decode
    /// to exactly the bytes the spec says.
    #[test]
    fn spec_conformance_vectors() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/envelope-v1.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors: invalid JSON");
        assert_eq!(doc["wire_version"].as_u64(), Some(u64::from(WIRE_VERSION)));

        let vectors = doc["vectors"].as_array().expect("vectors: not an array");
        assert!(!vectors.is_empty(), "vectors: empty");

        for v in vectors {
            let envelope = Envelope {
                kind: kind_by_name(v["kind"].as_str().expect("kind")),
                payload: unhex(v["payload"].as_str().expect("payload")),
            };
            let expected = unhex(v["encoded"].as_str().expect("encoded"));
            assert_eq!(encode(&envelope).as_deref(), Some(&expected[..]));
            assert_eq!(decode(&expected), Some(envelope));
        }
    }

    /// Every stream vector extracted from the spec must encode and
    /// decode to exactly the bytes the spec says, and round-trip.
    #[test]
    fn spec_stream_vectors() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/stream-v1.json"
        ));
        let doc: serde_json::Value =
            serde_json::from_str(raw).expect("stream vectors: invalid JSON");
        let streams = doc["streams"].as_array().expect("streams: not an array");
        assert!(!streams.is_empty(), "streams: empty");

        for s in streams {
            let envelopes: Vec<Envelope> = s["envelopes"]
                .as_array()
                .expect("envelopes")
                .iter()
                .map(|v| Envelope {
                    kind: kind_by_name(v["kind"].as_str().expect("kind")),
                    payload: unhex(v["payload"].as_str().expect("payload")),
                })
                .collect();
            let expected = unhex(s["encoded"].as_str().expect("encoded"));
            assert_eq!(encode_stream(&envelopes).as_deref(), Some(&expected[..]));
            assert_eq!(decode_stream(&expected), Some(envelopes));
        }
    }

    #[test]
    fn stream_rejects_trailing_garbage() {
        let mut bytes = encode_stream(&[Envelope {
            kind: Kind::Dm,
            payload: vec![1, 2, 3],
        }])
        .unwrap();
        bytes.push(0xff); // a lone trailing byte cannot start an envelope
        assert_eq!(decode_stream(&bytes), None);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = encode(&Envelope {
            kind: Kind::Dm,
            payload: vec![1, 2, 3],
        })
        .unwrap();
        bytes[1] = 2;
        assert_eq!(decode(&bytes), None);
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut bytes = encode(&Envelope {
            kind: Kind::Dm,
            payload: vec![],
        })
        .unwrap();
        bytes[2] = 0;
        assert_eq!(decode(&bytes), None);
    }

    #[test]
    fn rejects_length_mismatch_and_truncation() {
        let bytes = encode(&Envelope {
            kind: Kind::Group,
            payload: vec![9; 16],
        })
        .unwrap();
        assert_eq!(decode(&bytes[..bytes.len() - 1]), None); // truncated
        let mut extended = bytes.clone();
        extended.push(0); // trailing byte
        assert_eq!(decode(&extended), None);
        assert_eq!(decode(&bytes[..HEADER_LEN - 1]), None); // short header
        assert_eq!(decode(&[]), None);
    }
}
