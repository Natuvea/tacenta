//! Multi-device user state: the generic machine from `tacenta-state`
//! (the verified zone), instantiated at this crate's envelope type.
//! The trace vectors extracted from the spec
//! (`contracts/vectors/user-v1.json`) are replayed below.

use tacenta_wire::Envelope;

/// Multi-device delivery state over envelopes.
pub type User = tacenta_state::User<Envelope>;

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_wire::Kind;

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

    fn envelope_from(v: &serde_json::Value) -> Envelope {
        Envelope {
            kind: kind_by_name(v["kind"].as_str().expect("kind")),
            payload: unhex(v["payload"].as_str().expect("payload")),
        }
    }

    fn as_usize(v: &serde_json::Value) -> usize {
        usize::try_from(v.as_u64().expect("number")).expect("range")
    }

    /// Replay every trace extracted from the Lean spec: each op must be
    /// accepted or rejected exactly as the spec says, and the final
    /// cursors, delivered count, and per-device pending must match.
    #[test]
    fn spec_trace_vectors() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/user-v1.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors: invalid JSON");
        let traces = doc["traces"].as_array().expect("traces: not an array");
        assert!(!traces.is_empty(), "traces: empty");

        for trace in traces {
            let mut user = User::new();
            for op in trace["ops"].as_array().expect("ops") {
                match op["op"].as_str().expect("op") {
                    "link" => {
                        user.link_device();
                    }
                    "append" => user.append(envelope_from(op)),
                    "ack" => {
                        let d = as_usize(&op["device"]);
                        let n = as_usize(&op["n"]);
                        let expected = op["accepted"].as_bool().expect("accepted");
                        assert_eq!(user.ack(d, n), expected, "ack({d}, {n}) mismatch");
                    }
                    other => panic!("unknown op in vectors: {other}"),
                }
            }
            let final_state = &trace["final"];
            let expected_cursors: Vec<usize> = final_state["cursors"]
                .as_array()
                .expect("cursors")
                .iter()
                .map(as_usize)
                .collect();
            assert_eq!(user.cursors(), &expected_cursors[..]);
            assert_eq!(user.delivered(), as_usize(&final_state["delivered"]));
            let pending_per_device = final_state["pending_per_device"]
                .as_array()
                .expect("pending_per_device");
            assert_eq!(pending_per_device.len(), user.cursors().len());
            for (d, expected) in pending_per_device.iter().enumerate() {
                let expected: Vec<Envelope> = expected
                    .as_array()
                    .expect("device pending")
                    .iter()
                    .map(envelope_from)
                    .collect();
                assert_eq!(user.device_pending(d), &expected[..], "device {d}");
            }
        }
    }

    /// Mirror of the spec theorem `cursorOf_ack?_frame`: one device's
    /// ack never moves another device's cursor.
    #[test]
    fn ack_isolation_between_devices() {
        let mut u = User::new();
        u.link_device();
        u.link_device();
        u.append(Envelope {
            kind: Kind::Dm,
            payload: vec![1],
        });
        let before = u.cursors()[1];
        assert!(u.ack(0, 1));
        assert_eq!(u.cursors()[1], before);
    }

    /// Mirror of the spec theorem `delivered_linkDevice`: linking a
    /// device never un-delivers.
    #[test]
    fn linking_never_undelivers() {
        let mut u = User::new();
        u.link_device();
        u.append(Envelope {
            kind: Kind::Dm,
            payload: vec![1],
        });
        assert!(u.ack(0, 1));
        let before = u.delivered();
        u.link_device();
        assert_eq!(u.delivered(), before);
    }
}
