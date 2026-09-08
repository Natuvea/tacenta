//! Per-device session state: the generic machine from `tacenta-state`
//! (the verified zone), instantiated at this crate's envelope type.
//! The trace vectors extracted from the spec
//! (`contracts/vectors/session-v1.json`) are replayed below.

use tacenta_wire::Envelope;

/// Per-device delivery state over envelopes.
pub type Session = tacenta_state::Session<Envelope>;

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

    /// Replay every trace extracted from the Lean spec: each op must be
    /// accepted or rejected exactly as the spec says, and the final
    /// cursor and pending list must match.
    #[test]
    fn spec_trace_vectors() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/session-v1.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors: invalid JSON");
        let traces = doc["traces"].as_array().expect("traces: not an array");
        assert!(!traces.is_empty(), "traces: empty");

        for trace in traces {
            let mut session = Session::new();
            for op in trace["ops"].as_array().expect("ops") {
                match op["op"].as_str().expect("op") {
                    "append" => session.append(envelope_from(op)),
                    "ack" => {
                        let n = usize::try_from(op["n"].as_u64().expect("n")).expect("n range");
                        let expected = op["accepted"].as_bool().expect("accepted");
                        assert_eq!(session.ack(n), expected, "ack({n}) acceptance mismatch");
                    }
                    other => panic!("unknown op in vectors: {other}"),
                }
            }
            let final_state = &trace["final"];
            let expected_cursor =
                usize::try_from(final_state["cursor"].as_u64().expect("cursor")).expect("range");
            let expected_pending: Vec<Envelope> = final_state["pending"]
                .as_array()
                .expect("pending")
                .iter()
                .map(envelope_from)
                .collect();
            assert_eq!(session.cursor(), expected_cursor);
            assert_eq!(session.pending(), &expected_pending[..]);
        }
    }

    /// Mirror of the spec theorem `pending_append`: appends never
    /// disturb what is already pending.
    #[test]
    fn append_preserves_pending() {
        let mut s = Session::new();
        s.append(Envelope {
            kind: Kind::Dm,
            payload: vec![1],
        });
        s.append(Envelope {
            kind: Kind::Dm,
            payload: vec![2],
        });
        assert!(s.ack(1));
        let before = s.pending().to_vec();
        s.append(Envelope {
            kind: Kind::Group,
            payload: vec![3],
        });
        assert_eq!(&s.pending()[..before.len()], &before[..]);
        assert_eq!(s.pending().len(), before.len() + 1);
    }

    /// Mirror of the spec theorem `ack?_rejects`: rejected acks are
    /// exact no-ops.
    #[test]
    fn rejected_ack_is_a_no_op() {
        let mut s = Session::new();
        s.append(Envelope {
            kind: Kind::Dm,
            payload: vec![7],
        });
        assert!(s.ack(1));
        let snapshot = s.clone();
        assert!(!s.ack(0)); // rewind
        assert!(!s.ack(1)); // not advancing
        assert!(!s.ack(2)); // beyond the log
        assert_eq!(s, snapshot);
    }
}
