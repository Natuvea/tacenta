//! The product-facing route to standalone bounded group commitments.
//!
//! Product code supplies already canonical roster or application-context bytes.
//! Parsing, identity binding, and membership policy stay outside this adapter.

/// Computes the standalone core's domain-separated commitment of a canonical
/// bounded group roster preimage.
pub fn roster_commitment(preimage: &[u8]) -> [u8; 32] {
    open_tacenta::groups::roster_commitment(preimage)
}

/// Computes the standalone core's domain-separated commitment of a canonical
/// bounded group application context.
pub fn payload_commitment(context: &[u8]) -> [u8; 32] {
    open_tacenta::groups::payload_commitment(context)
}

#[cfg(test)]
mod tests {
    use super::{payload_commitment, roster_commitment};

    #[test]
    fn the_adapter_uses_distinct_core_domains() {
        assert_ne!(
            roster_commitment(b"same canonical value"),
            payload_commitment(b"same canonical value")
        );
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// The commitments in the group wire vectors
    /// (`contracts/vectors/group-wire-v1.json`, section 13 of
    /// `spec/group-wire-formats.md`) are the ones the core computes: SHA-256 over
    /// its fixed label and the bytes of a roster preimage or an application
    /// context.
    #[test]
    fn the_group_wire_vectors_commitments_are_the_cores() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/group-wire-v1.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors: invalid JSON");
        let entries = doc["commitments"].as_array().expect("commitments");
        assert!(entries.len() >= 3, "commitments: too few entries");
        let (mut rosters, mut contexts) = (0, 0);
        for entry in entries {
            let preimage = unhex(entry["preimage"].as_str().expect("preimage"));
            let digest = unhex(entry["digest"].as_str().expect("digest"));
            match entry["kind"].as_str().expect("kind") {
                "roster" => {
                    rosters += 1;
                    assert_eq!(roster_commitment(&preimage).to_vec(), digest);
                }
                "payload" => {
                    contexts += 1;
                    assert_eq!(payload_commitment(&preimage).to_vec(), digest);
                }
                other => panic!("unknown commitment kind {other}"),
            }
        }
        assert!(rosters >= 2 && contexts >= 1, "commitments: kinds missing");
    }
}
