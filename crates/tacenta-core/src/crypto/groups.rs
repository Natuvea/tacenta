//! The product-facing route to the standalone core's group helpers.
//!
//! Two things live here. At the top level, the bounded group commitments: product
//! code supplies already canonical roster or application-context bytes, and
//! parsing, identity binding and membership policy stay outside this adapter. In
//! [`inventory`], the hosted device-inventory statements.

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

/// Canonical hosted device-inventory statements. The standalone core owns the
/// encoding and issuer-signature verification; product services own account
/// authorization, durable lifecycle state, and directory publication.
pub mod inventory {
    pub use open_tacenta::groups::inventory::{
        BINDING_COMMITMENT_LABEL, DeviceBinding, Error, GROUP_EPOCH_V1, INVENTORY_DOMAIN,
        InventoryStatement, MAX_ACCOUNT_BYTES, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS,
        Revocation,
    };

    /// The core's rule for what may be admitted as an identity key (check 6 of
    /// "Accepting a signed statement" in identities-and-devices.md). An issuer
    /// applies it to a device's key when it links the device, before there is a
    /// statement to sign. This is the core's function, re-exported, not a copy
    /// of it.
    pub use open_tacenta::groups::inventory::validate_identity_key;

    /// Commit the exact canonical binding a replacement retires.
    pub fn binding_commitment(binding: &DeviceBinding) -> Result<[u8; 32], Error> {
        open_tacenta::groups::inventory::binding_commitment(binding)
    }

    /// Derive the pinned public key corresponding to a deployment-held issuer
    /// secret. The secret stays with the service; callers distribute only this
    /// 32-byte value and its configured key identifier to clients.
    pub fn issuer_public_key(issuer_secret: &[u8; 32]) -> [u8; 32] {
        open_tacenta::primitives::dh::PrivateKey::from_bytes(*issuer_secret)
            .public_key()
            .as_bytes()
            .to_owned()
    }
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
