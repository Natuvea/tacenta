//! Byte-level vectors for the first slice of the group wire formats
//! (`spec/group-wire-formats.md`, decision 0149).
//!
//! `contracts/vectors/group-wire-v1.json` is not generated from the Lean model,
//! which has no bytes (decision 0137, item 11). This file holds a hand-written
//! builder that writes every byte string from the layouts of the specification
//! page, field by field, and never calls a production encoder. It does two
//! things:
//!
//! * `committed_vectors_are_current` rebuilds the whole file and compares it with
//!   the committed one. `TACENTA_WRITE_GROUP_WIRE_VECTORS=1 cargo test -p
//!   tacenta-group --test group_wire_vectors` rewrites the file instead.
//! * `production_codecs_replay_every_committed_vector` reads the committed file
//!   (not this builder) and checks the production decoders and encoders against
//!   it: the decoder returns the stated fields or the stated refusal, and the
//!   encoder returns exactly the stated bytes or the stated refusal.
//!
//! A second reader written from the specification page alone replays the same
//! file (`tooling/check-group-wire-vectors.sh`).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use tacenta_group::{
    ApplicationContext, DIGEST_LEN, Error, GROUP_ID_LEN, GroupId, GroupPayload, Invitation,
    InvitationAcceptance, InvitationBootstrap, InvitationId, InvitationRevocation,
    InvitationStatus, LogicalSend, MAX_APPLICATION_CONTEXT_LEN, MAX_DEVICE_LEN, MAX_IDENTITY_LEN,
    MAX_MEMBERS, MAX_PAYLOAD_LEN, MAX_ROSTER_LEN, Member, POLICY_VERSION_V1, RESERVED_REVISION,
    Roster,
};

const FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/vectors/group-wire-v1.json"
);
const WRITE_ENV: &str = "TACENTA_WRITE_GROUP_WIRE_VECTORS";

/// The roster commitments the vectors chain through, as SHA-256 over the label
/// and the bytes of section 13 of the page. They are checked against
/// tacenta-core's functions in `tacenta-core`, and against the page's
/// definition by the second reader.
const D_GENESIS: &str = "e1d3bb2c88e0e146e1587d18d8ea9c8b45bee978390dcd8d3bc3f264b4927ae6";
const D_REV1: &str = "7ff8509a5262d32cfc5bf6c87a3da5e6cf554f954056686957565c843ae740c5";
const D_HELLO: &str = "cd501c6ac2d48536132c316cde4571c68a252f51c7d0d992c0ff8a52cb16ad14";

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

// ---------------------------------------------------------------------------
// The builder: one method per primitive of section 1 of the page.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Self::default()
    }
    fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }
    fn u8(self, n: u8) -> Self {
        self.raw(&[n])
    }
    fn u32(self, n: u32) -> Self {
        self.raw(&n.to_be_bytes())
    }
    fn u64(self, n: u64) -> Self {
        self.raw(&n.to_be_bytes())
    }
    fn lp32(self, bytes: &[u8]) -> Self {
        let n = u32::try_from(bytes.len()).expect("u32");
        self.u32(n).raw(bytes)
    }
    fn lp16(self, bytes: &[u8]) -> Self {
        let n = u16::try_from(bytes.len()).expect("u16");
        self.raw(&n.to_be_bytes()).raw(bytes)
    }
    fn member(self, m: &M) -> Self {
        self.lp32(&m.id).lp32(&m.dev)
    }
    fn members(mut self, ms: &[M]) -> Self {
        for m in ms {
            self = self.member(m);
        }
        self
    }
    fn done(self) -> Vec<u8> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Test-side field records. They hold raw byte vectors so that a vector can
// state a value no production type would accept.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct M {
    id: Vec<u8>,
    dev: Vec<u8>,
}

fn m(id: &[u8], dev: &[u8]) -> M {
    M {
        id: id.to_vec(),
        dev: dev.to_vec(),
    }
}

fn alice() -> M {
    m(b"alice", &[1])
}
fn bob() -> M {
    m(b"bob", &[1])
}
fn carol() -> M {
    m(b"carol", &[1])
}

const G: &[u8] = b"bounded-group-id";

fn fill(n: u8) -> Vec<u8> {
    vec![n; 32]
}

#[derive(Clone)]
struct RosterSpec {
    group: Vec<u8>,
    rev: u64,
    pred: Vec<u8>,
    authority: M,
    policy: u32,
    closed: u8,
    count: Option<u32>,
    members: Vec<M>,
}

impl RosterSpec {
    fn bytes(&self) -> Vec<u8> {
        Buf::new()
            .raw(b"Tacenta Group Roster v1")
            .lp32(&self.group)
            .u64(self.rev)
            .lp32(&self.pred)
            .member(&self.authority)
            .u32(self.policy)
            .u8(self.closed)
            .u32(self.count.unwrap_or(self.members.len() as u32))
            .members(&self.members)
            .done()
    }
    fn json(&self) -> Value {
        json!({
            "group_id": hex(&self.group),
            "revision": self.rev.to_string(),
            "predecessor_digest": hex(&self.pred),
            "authority": m_json(&self.authority),
            "policy_version": self.policy,
            "closed": self.closed == 1,
            "members": self.members.iter().map(m_json).collect::<Vec<_>>(),
        })
    }
}

fn m_json(member: &M) -> Value {
    json!({"identity": hex(&member.id), "device": hex(&member.dev)})
}

fn genesis() -> RosterSpec {
    RosterSpec {
        group: G.to_vec(),
        rev: 0,
        pred: vec![0; 32],
        authority: alice(),
        policy: 1,
        closed: 0,
        count: None,
        members: vec![alice()],
    }
}

fn rev1() -> RosterSpec {
    RosterSpec {
        rev: 1,
        pred: unhex(D_GENESIS),
        members: vec![alice(), bob()],
        ..genesis()
    }
}

fn small_members(count: u8) -> Vec<M> {
    (1..=count).map(|i| m(&[b'm', i], &[1])).collect()
}

fn big_members(count: u8) -> Vec<M> {
    (1..=count).map(|i| m(&[i; 256], &[i; 64])).collect()
}

fn roster_of(members: Vec<M>) -> RosterSpec {
    RosterSpec {
        rev: 1,
        pred: fill(0x11),
        authority: members[0].clone(),
        members,
        ..genesis()
    }
}

#[derive(Clone)]
struct CtxSpec {
    group: Vec<u8>,
    rev: u64,
    digest: Vec<u8>,
    sender: M,
    recipient: M,
    seq: u64,
    payload: Vec<u8>,
}

impl CtxSpec {
    fn bytes(&self) -> Vec<u8> {
        Buf::new()
            .raw(b"Tacenta Group Application v1")
            .lp32(&self.group)
            .u64(self.rev)
            .lp32(&self.digest)
            .member(&self.sender)
            .member(&self.recipient)
            .u64(self.seq)
            .lp32(&self.payload)
            .done()
    }
    fn json(&self) -> Value {
        json!({
            "group_id": hex(&self.group),
            "revision": self.rev.to_string(),
            "roster_digest": hex(&self.digest),
            "sender": m_json(&self.sender),
            "recipient": m_json(&self.recipient),
            "logical_sequence": self.seq.to_string(),
            "payload": hex(&self.payload),
        })
    }
}

fn hello() -> CtxSpec {
    CtxSpec {
        group: G.to_vec(),
        rev: 1,
        digest: unhex(D_REV1),
        sender: alice(),
        recipient: bob(),
        seq: 9,
        payload: b"hello".to_vec(),
    }
}

#[derive(Clone)]
struct BootSpec {
    id: Vec<u8>,
    group: Vec<u8>,
    target: M,
    src_rev: u64,
    src_digest: Vec<u8>,
    policy: u32,
    expires: u64,
    roster: RosterSpec,
    /// Replaces the embedded roster bytes (not the fields) when set.
    roster_bytes: Option<Vec<u8>>,
    /// Replaces the roster length prefix when set.
    roster_len: Option<u32>,
}

impl BootSpec {
    fn bytes(&self) -> Vec<u8> {
        let roster = self
            .roster_bytes
            .clone()
            .unwrap_or_else(|| self.roster.bytes());
        Buf::new()
            .raw(b"Tacenta Group Invitation Bootstrap v1")
            .raw(&self.id)
            .raw(&self.group)
            .lp16(&self.target.id)
            .lp16(&self.target.dev)
            .u64(self.src_rev)
            .raw(&self.src_digest)
            .u32(self.policy)
            .u64(self.expires)
            .u32(self.roster_len.unwrap_or(roster.len() as u32))
            .raw(&roster)
            .done()
    }
    fn json(&self) -> Value {
        json!({
            "invitation_id": hex(&self.id),
            "group_id": hex(&self.group),
            "target": m_json(&self.target),
            "source_revision": self.src_rev.to_string(),
            "source_roster_digest": hex(&self.src_digest),
            "policy_version": self.policy,
            "expires_at": self.expires.to_string(),
            "source_roster": self.roster.json(),
        })
    }
}

fn boot() -> BootSpec {
    BootSpec {
        id: vec![7; 16],
        group: G.to_vec(),
        target: bob(),
        src_rev: 0,
        src_digest: unhex(D_GENESIS),
        policy: 1,
        expires: 10,
        roster: genesis(),
        roster_bytes: None,
        roster_len: None,
    }
}

#[derive(Clone)]
struct AckSpec {
    domain: &'static [u8],
    group: Vec<u8>,
    id: Vec<u8>,
    rev: u64,
    digest: Vec<u8>,
}

const ACCEPT_DOMAIN: &[u8] = b"Tacenta Group Invitation Acceptance v1";
const REVOKE_DOMAIN: &[u8] = b"Tacenta Group Invitation Revocation v1";

impl AckSpec {
    fn new(domain: &'static [u8]) -> Self {
        Self {
            domain,
            group: G.to_vec(),
            id: vec![9; 16],
            rev: 0,
            digest: unhex(D_GENESIS),
        }
    }
    fn bytes(&self) -> Vec<u8> {
        Buf::new()
            .raw(self.domain)
            .raw(&self.group)
            .raw(&self.id)
            .u64(self.rev)
            .raw(&self.digest)
            .done()
    }
    fn json(&self) -> Value {
        json!({
            "group_id": hex(&self.group),
            "invitation_id": hex(&self.id),
            "source_revision": self.rev.to_string(),
            "source_roster_digest": hex(&self.digest),
        })
    }
}

#[derive(Clone)]
struct IntentSpec {
    group: Vec<u8>,
    rev: u64,
    sender: M,
    seq: u64,
    digest: Vec<u8>,
    payload: Vec<u8>,
    count: Option<u32>,
    recipients: Vec<M>,
}

impl IntentSpec {
    fn bytes(&self) -> Vec<u8> {
        Buf::new()
            .raw(b"Tacenta Group Logical Send v1")
            .lp32(&self.group)
            .u64(self.rev)
            .member(&self.sender)
            .u64(self.seq)
            .lp32(&self.digest)
            .lp32(&self.payload)
            .u32(self.count.unwrap_or(self.recipients.len() as u32))
            .members(&self.recipients)
            .done()
    }
    fn json(&self) -> Value {
        json!({
            "group_id": hex(&self.group),
            "revision": self.rev.to_string(),
            "sender": m_json(&self.sender),
            "sequence": self.seq.to_string(),
            "roster_digest": hex(&self.digest),
            "payload": hex(&self.payload),
            "recipients": self.recipients.iter().map(m_json).collect::<Vec<_>>(),
        })
    }
}

fn intent() -> IntentSpec {
    IntentSpec {
        group: G.to_vec(),
        rev: 1,
        sender: alice(),
        seq: 3,
        digest: unhex(D_REV1),
        payload: b"hi".to_vec(),
        count: None,
        recipients: vec![bob()],
    }
}

fn payload_bytes(tag: u8, value: &[u8]) -> Vec<u8> {
    Buf::new()
        .raw(b"Tacenta Group Payload v1")
        .u8(tag)
        .lp32(value)
        .done()
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

enum Res {
    Valid {
        bytes: Vec<u8>,
        fields: Value,
    },
    Refuse {
        bytes: Vec<u8>,
        pad_to: Option<usize>,
        reason: &'static str,
    },
    RefusePrefixes {
        bytes: Vec<u8>,
        reason: &'static str,
    },
    EncodeRefuse {
        fields: Value,
        reason: &'static str,
    },
}

struct Vector {
    name: String,
    format: &'static str,
    res: Res,
}

impl Vector {
    fn line(&self) -> String {
        let s = |text: &str| serde_json::to_string(text).expect("string");
        let head = format!(
            "{{\"name\": {}, \"format\": {}, \"result\": ",
            s(&self.name),
            s(self.format)
        );
        match &self.res {
            Res::Valid { bytes, fields } => format!(
                "{head}\"valid\", \"bytes\": \"{}\", \"fields\": {}}}",
                hex(bytes),
                serde_json::to_string(fields).expect("json")
            ),
            Res::Refuse {
                bytes,
                pad_to,
                reason,
            } => {
                let pad = pad_to.map_or(String::new(), |n| format!(", \"pad_to\": {n}"));
                format!(
                    "{head}\"refuse\", \"bytes\": \"{}\"{pad}, \"reason\": {}}}",
                    hex(bytes),
                    s(reason)
                )
            }
            Res::RefusePrefixes { bytes, reason } => format!(
                "{head}\"refuse_prefixes\", \"bytes\": \"{}\", \"reason\": {}}}",
                hex(bytes),
                s(reason)
            ),
            Res::EncodeRefuse { fields, reason } => format!(
                "{head}\"encode_refuse\", \"fields\": {}, \"reason\": {}}}",
                serde_json::to_string(fields).expect("json"),
                s(reason)
            ),
        }
    }
}

#[derive(Default)]
struct Corpus(Vec<Vector>);

impl Corpus {
    fn valid(&mut self, name: &str, format: &'static str, bytes: Vec<u8>, fields: Value) {
        self.push(name, format, Res::Valid { bytes, fields });
    }
    fn refuse(&mut self, name: &str, format: &'static str, bytes: Vec<u8>, reason: &'static str) {
        self.push(
            name,
            format,
            Res::Refuse {
                bytes,
                pad_to: None,
                reason,
            },
        );
    }
    fn refuse_padded(
        &mut self,
        name: &str,
        format: &'static str,
        bytes: Vec<u8>,
        pad_to: usize,
        reason: &'static str,
    ) {
        self.push(
            name,
            format,
            Res::Refuse {
                bytes,
                pad_to: Some(pad_to),
                reason,
            },
        );
    }
    fn prefixes(&mut self, name: &str, format: &'static str, bytes: Vec<u8>, reason: &'static str) {
        self.push(name, format, Res::RefusePrefixes { bytes, reason });
    }
    fn encode_refuse(
        &mut self,
        name: &str,
        format: &'static str,
        fields: Value,
        reason: &'static str,
    ) {
        self.push(
            &format!("encode-{name}"),
            format,
            Res::EncodeRefuse { fields, reason },
        );
    }
    /// A fault that the decoder refuses in the bytes and the encoder refuses in
    /// the fields, with the same reason: two vectors of one name. Section 3 of
    /// the page requires the encoder not to write what its decoder refuses, and
    /// `every_encoder_refusal_has_a_decoder_twin` holds the file to it.
    fn refuse_both(
        &mut self,
        name: &str,
        format: &'static str,
        bytes: Vec<u8>,
        fields: Value,
        reason: &'static str,
    ) {
        self.refuse(name, format, bytes, reason);
        self.encode_refuse(name, format, fields, reason);
    }
    fn push(&mut self, name: &str, format: &'static str, res: Res) {
        self.0.push(Vector {
            name: format!("{format}/{name}"),
            format,
            res,
        });
    }
}

fn roster_corpus(c: &mut Corpus) {
    let f = "roster";
    let g0 = genesis();
    let r1 = rev1();

    c.valid("genesis", f, g0.bytes(), g0.json());
    c.valid("two-members-revision-1", f, r1.bytes(), r1.json());
    let empty = RosterSpec {
        authority: m(b"", b""),
        members: vec![m(b"", b"")],
        ..genesis()
    };
    c.valid("empty-identity-and-device", f, empty.bytes(), empty.json());
    let outside = RosterSpec {
        authority: m(b"zed", &[1]),
        ..rev1()
    };
    c.valid(
        "authority-outside-members",
        f,
        outside.bytes(),
        outside.json(),
    );
    let none = RosterSpec {
        rev: 2,
        closed: 1,
        members: vec![],
        ..rev1()
    };
    c.valid("closed-with-no-members", f, none.bytes(), none.json());
    let closed = RosterSpec {
        rev: 3,
        closed: 1,
        ..rev1()
    };
    c.valid("closed-with-members", f, closed.bytes(), closed.json());
    let top = RosterSpec {
        rev: u64::MAX - 1,
        ..rev1()
    };
    c.valid("highest-usable-revision", f, top.bytes(), top.json());
    let eight = roster_of(small_members(8));
    c.valid("eight-members", f, eight.bytes(), eight.json());
    let biggest = roster_of(big_members(8));
    assert_eq!(biggest.bytes().len(), 3_048);
    c.valid(
        "eight-members-maximum-size-3048",
        f,
        biggest.bytes(),
        biggest.json(),
    );
    let wide = RosterSpec {
        rev: 0,
        pred: vec![0; 32],
        authority: big_members(1)[0].clone(),
        members: big_members(1),
        ..genesis()
    };
    c.valid("authority-256-and-64", f, wide.bytes(), wide.json());
    // Member order is the pair, not the concatenation (decision 0136).
    let prefix_id = roster_of(vec![m(b"a", &[0xff]), m(b"ab", b"")]);
    c.valid(
        "order-is-pair-not-concatenation-prefix-identity",
        f,
        prefix_id.bytes(),
        prefix_id.json(),
    );
    let same_concat = roster_of(vec![m(b"a", b"bc"), m(b"ab", b"c")]);
    c.valid(
        "order-is-pair-not-concatenation-equal-concatenations",
        f,
        same_concat.bytes(),
        same_concat.json(),
    );

    // Truncation and framing.
    c.refuse("empty-input", f, vec![], "malformed");
    c.prefixes("every-proper-prefix", f, r1.bytes(), "malformed");
    let mut bad_domain = r1.bytes();
    bad_domain[22] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    c.refuse(
        "domain-of-another-format",
        f,
        Buf::new()
            .raw(b"Tacenta Group Application v1")
            .raw(&r1.bytes()[23..])
            .done(),
        "malformed",
    );
    for n in [15usize, 17] {
        let bad = RosterSpec {
            group: vec![b'g'; n],
            ..r1.clone()
        };
        c.refuse(&format!("group-id-{n}-bytes"), f, bad.bytes(), "malformed");
    }
    for n in [31usize, 33] {
        let bad = RosterSpec {
            pred: vec![1; n],
            ..r1.clone()
        };
        c.refuse(
            &format!("predecessor-digest-{n}-bytes"),
            f,
            bad.bytes(),
            "malformed",
        );
    }
    for closed in [2u8, 255] {
        let bad = RosterSpec {
            closed,
            ..r1.clone()
        };
        c.refuse(
            &format!("closed-byte-{closed}"),
            f,
            bad.bytes(),
            "malformed",
        );
    }
    let mut trailing = r1.bytes();
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing, "malformed");
    let short = RosterSpec {
        count: Some(3),
        ..r1.clone()
    };
    c.refuse(
        "member-count-exceeds-members-present",
        f,
        short.bytes(),
        "malformed",
    );
    c.refuse(
        "identity-length-exceeds-input",
        f,
        Buf::new()
            .raw(b"Tacenta Group Roster v1")
            .lp32(G)
            .u64(1)
            .lp32(&fill(0x11))
            .u32(300)
            .raw(b"alice")
            .done(),
        "malformed",
    );

    // Revision, policy, genesis.
    let reserved = RosterSpec {
        rev: u64::MAX,
        ..r1.clone()
    };
    c.refuse(
        "reserved-revision",
        f,
        reserved.bytes(),
        "reserved_revision",
    );
    c.encode_refuse("reserved-revision", f, reserved.json(), "reserved_revision");
    for policy in [0u32, 2] {
        let bad = RosterSpec {
            policy,
            ..r1.clone()
        };
        c.refuse(
            &format!("policy-version-{policy}"),
            f,
            bad.bytes(),
            "unsupported_policy",
        );
        c.encode_refuse(
            &format!("policy-version-{policy}"),
            f,
            bad.json(),
            "unsupported_policy",
        );
    }
    let two_at_zero = RosterSpec {
        members: vec![alice(), bob()],
        ..genesis()
    };
    c.refuse(
        "genesis-with-two-members",
        f,
        two_at_zero.bytes(),
        "invalid_genesis",
    );
    c.encode_refuse(
        "genesis-with-two-members",
        f,
        two_at_zero.json(),
        "invalid_genesis",
    );
    let closed_genesis = RosterSpec {
        closed: 1,
        ..genesis()
    };
    c.refuse(
        "genesis-closed",
        f,
        closed_genesis.bytes(),
        "invalid_genesis",
    );
    c.encode_refuse(
        "genesis-closed",
        f,
        closed_genesis.json(),
        "invalid_genesis",
    );
    let pred_genesis = RosterSpec {
        pred: fill(1),
        ..genesis()
    };
    c.refuse(
        "genesis-nonzero-predecessor",
        f,
        pred_genesis.bytes(),
        "invalid_genesis",
    );
    c.encode_refuse(
        "genesis-nonzero-predecessor",
        f,
        pred_genesis.json(),
        "invalid_genesis",
    );
    let other_genesis = RosterSpec {
        members: vec![bob()],
        ..genesis()
    };
    c.refuse(
        "genesis-member-is-not-the-authority",
        f,
        other_genesis.bytes(),
        "invalid_genesis",
    );
    let device_genesis = RosterSpec {
        members: vec![m(b"alice", &[2])],
        ..genesis()
    };
    c.refuse(
        "genesis-member-differs-in-device-only",
        f,
        device_genesis.bytes(),
        "invalid_genesis",
    );
    let no_genesis = RosterSpec {
        members: vec![],
        ..genesis()
    };
    c.refuse(
        "genesis-with-no-members",
        f,
        no_genesis.bytes(),
        "invalid_genesis",
    );
    // Precedence (section 5, step 12).
    let policy_first = RosterSpec {
        policy: 2,
        members: vec![alice(), bob()],
        ..genesis()
    };
    c.refuse(
        "precedence-policy-before-genesis",
        f,
        policy_first.bytes(),
        "unsupported_policy",
    );
    let reserved_first = RosterSpec {
        rev: u64::MAX,
        policy: 2,
        ..r1.clone()
    };
    c.refuse(
        "precedence-reserved-revision-before-policy",
        f,
        reserved_first.bytes(),
        "reserved_revision",
    );

    // Member count.
    c.refuse(
        "nine-members-declared-none-present",
        f,
        RosterSpec {
            count: Some(9),
            members: vec![],
            ..r1.clone()
        }
        .bytes(),
        "too_many_members",
    );
    let nine = roster_of(small_members(9));
    c.refuse("nine-members", f, nine.bytes(), "too_many_members");
    c.encode_refuse("nine-members", f, nine.json(), "too_many_members");
    c.refuse(
        "member-count-4294967295",
        f,
        RosterSpec {
            count: Some(u32::MAX),
            members: vec![],
            ..r1.clone()
        }
        .bytes(),
        "too_many_members",
    );

    // Order and uniqueness, at the first pair, a middle pair and the last pair.
    let unsorted_first = RosterSpec {
        members: vec![bob(), alice()],
        ..r1.clone()
    };
    c.refuse(
        "unsorted-first-pair",
        f,
        unsorted_first.bytes(),
        "non_canonical",
    );
    c.encode_refuse(
        "unsorted-first-pair",
        f,
        unsorted_first.json(),
        "non_canonical",
    );
    for (label, swap) in [("middle", 3usize), ("last", 6)] {
        let mut members = small_members(8);
        members.swap(swap, swap + 1);
        let bad = roster_of(members);
        c.refuse(
            &format!("unsorted-{label}-pair-of-eight"),
            f,
            bad.bytes(),
            "non_canonical",
        );
    }
    let exact_duplicate = RosterSpec {
        members: vec![alice(), alice()],
        ..r1.clone()
    };
    c.refuse(
        "duplicate-member",
        f,
        exact_duplicate.bytes(),
        "non_canonical",
    );
    let second_device = RosterSpec {
        members: vec![alice(), m(b"alice", &[2])],
        ..r1.clone()
    };
    c.refuse(
        "same-identity-second-device",
        f,
        second_device.bytes(),
        "non_canonical",
    );
    c.encode_refuse(
        "same-identity-second-device",
        f,
        second_device.json(),
        "non_canonical",
    );
    let mut last_duplicate = small_members(7);
    last_duplicate.push(m(&[b'm', 7], &[2]));
    c.refuse(
        "same-identity-second-device-at-the-last-pair-of-eight",
        f,
        roster_of(last_duplicate).bytes(),
        "non_canonical",
    );
    let concat_order = roster_of(vec![m(b"ab", b""), m(b"a", &[0xff])]);
    c.refuse(
        "concatenation-order-is-refused",
        f,
        concat_order.bytes(),
        "non_canonical",
    );
    let separated = RosterSpec {
        members: vec![m(b"a", &[0]), m(&[b'a', 1], &[0]), m(b"a", &[2])],
        authority: m(b"a", &[0]),
        ..r1.clone()
    };
    c.refuse(
        "same-identity-separated-by-another",
        f,
        separated.bytes(),
        "non_canonical",
    );

    // Member sizes, at the authority, the first member and the last member.
    let wide_id = |n: usize| m(&vec![9; n], &[1]);
    let wide_dev = |n: usize| m(b"a", &vec![9; n]);
    for (label, id_reason_member) in [("256", 256usize), ("257", 257)] {
        let ok = id_reason_member == 256;
        let authority = RosterSpec {
            authority: wide_id(id_reason_member),
            ..r1.clone()
        };
        let first = RosterSpec {
            members: vec![wide_id(id_reason_member), bob()],
            ..r1.clone()
        };
        let mut last_members = small_members(7);
        last_members.push(m(&vec![0xff; id_reason_member], &[1]));
        let last = roster_of(last_members);
        if ok {
            c.valid(
                "identity-256-in-authority",
                f,
                authority.bytes(),
                authority.json(),
            );
            c.valid(
                "identity-256-in-first-member",
                f,
                first.bytes(),
                first.json(),
            );
            c.valid(
                "identity-256-in-last-of-eight",
                f,
                last.bytes(),
                last.json(),
            );
        } else {
            c.refuse(
                &format!("identity-{label}-in-authority"),
                f,
                authority.bytes(),
                "identity_too_large",
            );
            c.encode_refuse(
                &format!("identity-{label}-in-authority"),
                f,
                authority.json(),
                "identity_too_large",
            );
            c.refuse(
                &format!("identity-{label}-in-first-member"),
                f,
                first.bytes(),
                "identity_too_large",
            );
            c.encode_refuse(
                &format!("identity-{label}-in-first-member"),
                f,
                first.json(),
                "identity_too_large",
            );
            c.refuse(
                &format!("identity-{label}-in-last-of-eight"),
                f,
                last.bytes(),
                "identity_too_large",
            );
        }
    }
    for n in [64usize, 65] {
        let authority = RosterSpec {
            authority: wide_dev(n),
            ..r1.clone()
        };
        let first = RosterSpec {
            members: vec![wide_dev(n), bob()],
            ..r1.clone()
        };
        let mut last_members = small_members(7);
        last_members.push(m(&[b'n', 1], &vec![0xff; n]));
        let last = roster_of(last_members);
        if n == 64 {
            c.valid(
                "device-64-in-authority",
                f,
                authority.bytes(),
                authority.json(),
            );
            c.valid("device-64-in-first-member", f, first.bytes(), first.json());
            c.valid("device-64-in-last-of-eight", f, last.bytes(), last.json());
        } else {
            c.refuse(
                "device-65-in-authority",
                f,
                authority.bytes(),
                "device_too_large",
            );
            c.encode_refuse(
                "device-65-in-authority",
                f,
                authority.json(),
                "device_too_large",
            );
            c.refuse(
                "device-65-in-first-member",
                f,
                first.bytes(),
                "device_too_large",
            );
            c.encode_refuse(
                "device-65-in-first-member",
                f,
                first.json(),
                "device_too_large",
            );
            c.refuse(
                "device-65-in-last-of-eight",
                f,
                last.bytes(),
                "device_too_large",
            );
        }
    }
    let both_wide = RosterSpec {
        authority: m(&[9; 257], &[9; 65]),
        ..r1.clone()
    };
    c.refuse(
        "precedence-identity-size-before-device-size",
        f,
        both_wide.bytes(),
        "identity_too_large",
    );

    // Whole-input bound.
    for (name, total, reason) in [
        ("4096-bytes-with-trailing-zeros", 4096usize, "malformed"),
        ("4097-bytes", 4097, "roster_too_large"),
    ] {
        c.refuse_padded(name, f, r1.bytes(), total, reason);
    }
    c.refuse_padded(
        "4097-zero-bytes-size-before-domain",
        f,
        vec![],
        4097,
        "roster_too_large",
    );
    c.refuse_padded(
        "4096-zero-bytes-fail-the-domain",
        f,
        vec![],
        4096,
        "malformed",
    );
}

fn context_corpus(c: &mut Corpus) {
    let f = "context";
    let h = hello();
    c.valid("hello", f, h.bytes(), h.json());
    let minimal = CtxSpec {
        rev: 0,
        digest: vec![0; 32],
        seq: 0,
        payload: vec![],
        ..h.clone()
    };
    c.valid("minimal-empty-payload", f, minimal.bytes(), minimal.json());
    let top = CtxSpec {
        rev: u64::MAX - 1,
        seq: u64::MAX,
        ..h.clone()
    };
    c.valid("highest-revision-and-sequence", f, top.bytes(), top.json());
    let same = CtxSpec {
        recipient: alice(),
        ..h.clone()
    };
    c.valid("sender-equals-recipient", f, same.bytes(), same.json());
    let empty = CtxSpec {
        sender: m(b"", b""),
        recipient: m(b"", b""),
        ..h.clone()
    };
    c.valid("empty-identity-and-device", f, empty.bytes(), empty.json());
    let full = CtxSpec {
        payload: vec![0xa5; 1024],
        ..h.clone()
    };
    c.valid("payload-1024", f, full.bytes(), full.json());
    let biggest = CtxSpec {
        sender: big_members(1)[0].clone(),
        recipient: m(&[2; 256], &[2; 64]),
        payload: vec![0xa5; 1024],
        ..h.clone()
    };
    assert_eq!(biggest.bytes().len(), 1_784);
    c.valid("maximum-size-1784", f, biggest.bytes(), biggest.json());
    let over = CtxSpec {
        payload: vec![0xa5; 1025],
        ..h.clone()
    };
    c.refuse("payload-1025", f, over.bytes(), "payload_too_large");
    c.encode_refuse("payload-1025", f, over.json(), "payload_too_large");

    c.refuse("empty-input", f, vec![], "malformed");
    c.prefixes("every-proper-prefix", f, h.bytes(), "malformed");
    let mut trailing = h.bytes();
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing, "malformed");
    let mut bad_domain = h.bytes();
    bad_domain[27] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    for n in [15usize, 17] {
        let bad = CtxSpec {
            group: vec![b'g'; n],
            ..h.clone()
        };
        c.refuse(&format!("group-id-{n}-bytes"), f, bad.bytes(), "malformed");
    }
    for n in [31usize, 33] {
        let bad = CtxSpec {
            digest: vec![1; n],
            ..h.clone()
        };
        c.refuse(
            &format!("roster-digest-{n}-bytes"),
            f,
            bad.bytes(),
            "malformed",
        );
    }
    c.refuse(
        "payload-length-exceeds-input",
        f,
        Buf::new()
            .raw(b"Tacenta Group Application v1")
            .lp32(G)
            .u64(1)
            .lp32(&fill(1))
            .member(&alice())
            .member(&bob())
            .u64(0)
            .u32(10)
            .raw(b"short")
            .done(),
        "malformed",
    );
    let reserved = CtxSpec {
        rev: u64::MAX,
        ..h.clone()
    };
    c.refuse(
        "reserved-revision",
        f,
        reserved.bytes(),
        "reserved_revision",
    );
    c.encode_refuse("reserved-revision", f, reserved.json(), "reserved_revision");

    // Member sizes at the sender and at the recipient.
    for (label, member_id) in [("256", 256usize), ("257", 257)] {
        let sender = CtxSpec {
            sender: m(&vec![9; member_id], &[1]),
            ..h.clone()
        };
        let recipient = CtxSpec {
            recipient: m(&vec![9; member_id], &[1]),
            ..h.clone()
        };
        if member_id == 256 {
            c.valid("sender-identity-256", f, sender.bytes(), sender.json());
            c.valid(
                "recipient-identity-256",
                f,
                recipient.bytes(),
                recipient.json(),
            );
        } else {
            c.refuse(
                &format!("sender-identity-{label}"),
                f,
                sender.bytes(),
                "identity_too_large",
            );
            c.encode_refuse(
                &format!("sender-identity-{label}"),
                f,
                sender.json(),
                "identity_too_large",
            );
            c.refuse(
                &format!("recipient-identity-{label}"),
                f,
                recipient.bytes(),
                "identity_too_large",
            );
            c.encode_refuse(
                &format!("recipient-identity-{label}"),
                f,
                recipient.json(),
                "identity_too_large",
            );
        }
    }
    for n in [64usize, 65] {
        let sender = CtxSpec {
            sender: m(b"s", &vec![9; n]),
            ..h.clone()
        };
        let recipient = CtxSpec {
            recipient: m(b"r", &vec![9; n]),
            ..h.clone()
        };
        if n == 64 {
            c.valid("sender-device-64", f, sender.bytes(), sender.json());
            c.valid(
                "recipient-device-64",
                f,
                recipient.bytes(),
                recipient.json(),
            );
        } else {
            c.refuse("sender-device-65", f, sender.bytes(), "device_too_large");
            c.encode_refuse("sender-device-65", f, sender.json(), "device_too_large");
            c.refuse(
                "recipient-device-65",
                f,
                recipient.bytes(),
                "device_too_large",
            );
            c.encode_refuse(
                "recipient-device-65",
                f,
                recipient.json(),
                "device_too_large",
            );
        }
    }
    // Precedence.
    let reserved_and_big = CtxSpec {
        rev: u64::MAX,
        payload: vec![0; 1025],
        ..h.clone()
    };
    c.refuse(
        "precedence-reserved-revision-before-payload-size",
        f,
        reserved_and_big.bytes(),
        "reserved_revision",
    );
    c.encode_refuse(
        "precedence-reserved-revision-before-payload-size",
        f,
        reserved_and_big.json(),
        "reserved_revision",
    );
    let sender_and_payload = CtxSpec {
        sender: m(&vec![9; 257], &[1]),
        payload: vec![0; 1025],
        ..h.clone()
    };
    c.refuse(
        "precedence-decode-reads-sender-before-payload-size",
        f,
        sender_and_payload.bytes(),
        "identity_too_large",
    );
    c.encode_refuse(
        "precedence-encode-checks-payload-before-sender-size",
        f,
        sender_and_payload.json(),
        "payload_too_large",
    );

    // Whole-input bound.
    c.refuse_padded(
        "2048-bytes-with-trailing-zeros",
        f,
        h.bytes(),
        2048,
        "malformed",
    );
    c.refuse_padded("2049-bytes", f, h.bytes(), 2049, "context_too_large");
    c.refuse_padded(
        "2049-zero-bytes-size-before-domain",
        f,
        vec![],
        2049,
        "context_too_large",
    );
    c.refuse_padded(
        "2048-zero-bytes-fail-the-domain",
        f,
        vec![],
        2048,
        "malformed",
    );
}

fn bootstrap_corpus(c: &mut Corpus) {
    let f = "bootstrap";
    let b = boot();
    c.valid("genesis-source", f, b.bytes(), b.json());
    let r1 = BootSpec {
        src_rev: 1,
        src_digest: unhex(D_REV1),
        roster: rev1(),
        ..boot()
    };
    c.valid("revision-1-source", f, r1.bytes(), r1.json());
    let late = BootSpec {
        expires: u64::MAX,
        ..boot()
    };
    c.valid("expires-at-highest", f, late.bytes(), late.json());
    let empty = BootSpec {
        target: m(b"", b""),
        expires: 0,
        ..boot()
    };
    c.valid("empty-target", f, empty.bytes(), empty.json());
    let top = BootSpec {
        src_rev: u64::MAX - 1,
        roster: RosterSpec {
            rev: u64::MAX - 1,
            ..rev1()
        },
        ..boot()
    };
    c.valid("highest-usable-source-revision", f, top.bytes(), top.json());
    let biggest = BootSpec {
        target: big_members(1)[0].clone(),
        roster: roster_of(big_members(8)),
        src_rev: 1,
        ..boot()
    };
    assert_eq!(biggest.bytes().len(), 3_497);
    c.valid("maximum-size-3497", f, biggest.bytes(), biggest.json());
    let wide_target = BootSpec {
        target: m(&[3; 256], &[4; 64]),
        ..boot()
    };
    c.valid(
        "target-256-and-64",
        f,
        wide_target.bytes(),
        wide_target.json(),
    );

    c.refuse("empty-input", f, vec![], "malformed");
    c.prefixes("every-proper-prefix", f, r1.bytes(), "malformed");
    let mut trailing = b.bytes();
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing.clone(), "malformed");
    let mut bad_domain = b.bytes();
    bad_domain[36] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    c.refuse(
        "domain-of-acceptance",
        f,
        Buf::new().raw(ACCEPT_DOMAIN).raw(&b.bytes()[37..]).done(),
        "malformed",
    );

    // Bindings between the invitation and its source roster.
    let group_mismatch = BootSpec {
        group: vec![b'x'; 16],
        ..boot()
    };
    c.refuse(
        "group-id-differs-from-roster",
        f,
        group_mismatch.bytes(),
        "conflict",
    );
    c.encode_refuse(
        "group-id-differs-from-roster",
        f,
        group_mismatch.json(),
        "conflict",
    );
    let revision_mismatch = BootSpec {
        src_rev: 1,
        ..boot()
    };
    c.refuse(
        "source-revision-differs-from-roster",
        f,
        revision_mismatch.bytes(),
        "conflict",
    );
    c.encode_refuse(
        "source-revision-differs-from-roster",
        f,
        revision_mismatch.json(),
        "conflict",
    );
    let reserved = BootSpec {
        src_rev: u64::MAX,
        ..boot()
    };
    c.refuse_both(
        "reserved-source-revision",
        f,
        reserved.bytes(),
        reserved.json(),
        "reserved_revision",
    );
    let policy = BootSpec {
        policy: 2,
        ..boot()
    };
    c.refuse_both(
        "invitation-policy-version-2",
        f,
        policy.bytes(),
        policy.json(),
        "unsupported_policy",
    );
    let policy_zero = BootSpec {
        policy: 0,
        ..boot()
    };
    c.refuse_both(
        "invitation-policy-version-0",
        f,
        policy_zero.bytes(),
        policy_zero.json(),
        "unsupported_policy",
    );
    // Precedence (section 7, steps 9 to 11).
    let mut reserved_trailing = reserved.bytes();
    reserved_trailing.push(0);
    c.refuse(
        "precedence-trailing-bytes-before-reserved-revision",
        f,
        reserved_trailing,
        "malformed",
    );
    let reserved_and_group = BootSpec {
        src_rev: u64::MAX,
        group: vec![b'x'; 16],
        ..boot()
    };
    c.refuse_both(
        "precedence-reserved-revision-before-conflict",
        f,
        reserved_and_group.bytes(),
        reserved_and_group.json(),
        "reserved_revision",
    );
    let target_and_group = BootSpec {
        target: m(&vec![1; 257], &[1]),
        group: vec![b'x'; 16],
        ..boot()
    };
    c.refuse_both(
        "precedence-target-size-before-conflict",
        f,
        target_and_group.bytes(),
        target_and_group.json(),
        "identity_too_large",
    );

    // The target (short form, checked after the roster).
    let big_id = BootSpec {
        target: m(&vec![3; 257], &[1]),
        ..boot()
    };
    c.refuse_both(
        "target-identity-257",
        f,
        big_id.bytes(),
        big_id.json(),
        "identity_too_large",
    );
    let big_dev = BootSpec {
        target: m(b"bob", &[4; 65]),
        ..boot()
    };
    c.refuse_both(
        "target-device-65",
        f,
        big_dev.bytes(),
        big_dev.json(),
        "device_too_large",
    );
    let mut target_length = b.bytes();
    // The target identity length prefix sits after the domain and the two IDs.
    target_length[69..71].copy_from_slice(&500u16.to_be_bytes());
    c.refuse(
        "target-identity-length-exceeds-input",
        f,
        target_length[..80].to_vec(),
        "malformed",
    );

    // The embedded roster.
    c.refuse(
        "roster-length-exceeds-input",
        f,
        BootSpec {
            roster_len: Some(5_000),
            ..boot()
        }
        .bytes(),
        "malformed",
    );
    let bad_roster = RosterSpec {
        members: vec![bob(), alice()],
        ..rev1()
    };
    c.refuse(
        "embedded-roster-unsorted",
        f,
        BootSpec {
            src_rev: 1,
            roster: bad_roster,
            ..boot()
        }
        .bytes(),
        "non_canonical",
    );
    let bad_policy_roster = RosterSpec {
        policy: 2,
        ..genesis()
    };
    let policy_roster = BootSpec {
        roster: bad_policy_roster,
        ..boot()
    };
    c.refuse_both(
        "embedded-roster-policy-version-2",
        f,
        policy_roster.bytes(),
        policy_roster.json(),
        "unsupported_policy",
    );
    let mut roster_plus_one = genesis().bytes();
    roster_plus_one.push(0);
    c.refuse(
        "embedded-roster-with-a-trailing-byte",
        f,
        BootSpec {
            roster_bytes: Some(roster_plus_one),
            ..boot()
        }
        .bytes(),
        "malformed",
    );
    for (name, total, reason) in [
        ("embedded-roster-4096-bytes", 4096usize, "malformed"),
        ("embedded-roster-4097-bytes", 4097, "roster_too_large"),
    ] {
        let mut padded = genesis().bytes();
        padded.resize(total, 0);
        c.refuse(
            name,
            f,
            BootSpec {
                roster_bytes: Some(padded),
                ..boot()
            }
            .bytes(),
            reason,
        );
    }
}

fn ack_corpus(c: &mut Corpus, domain: &'static [u8], f: &'static str, other: &'static [u8]) {
    let a = AckSpec::new(domain);
    c.valid("revision-0", f, a.bytes(), a.json());
    let rich = AckSpec {
        group: b"another-group-id".to_vec(),
        id: (0..16).collect(),
        rev: 2,
        digest: unhex(D_REV1),
        ..a.clone()
    };
    c.valid("revision-2", f, rich.bytes(), rich.json());
    let top = AckSpec {
        rev: u64::MAX - 1,
        ..a.clone()
    };
    c.valid("highest-usable-revision", f, top.bytes(), top.json());
    assert_eq!(a.bytes().len(), 110);

    c.refuse("empty-input", f, vec![], "malformed");
    c.prefixes("every-proper-prefix", f, a.bytes(), "malformed");
    let mut trailing = a.bytes();
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing, "malformed");
    let other_domain = AckSpec::new(other);
    c.refuse(
        "the-other-invitation-domain",
        f,
        other_domain.bytes(),
        "malformed",
    );
    let mut bad_domain = a.bytes();
    bad_domain[37] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    let reserved = AckSpec {
        rev: u64::MAX,
        ..a.clone()
    };
    c.refuse(
        "reserved-revision",
        f,
        reserved.bytes(),
        "reserved_revision",
    );
    c.encode_refuse("reserved-revision", f, reserved.json(), "reserved_revision");
    let mut reserved_trailing = reserved.bytes();
    reserved_trailing.push(0);
    c.refuse(
        "precedence-trailing-byte-before-reserved-revision",
        f,
        reserved_trailing,
        "malformed",
    );
}

fn payload_corpus(c: &mut Corpus) {
    let f = "payload";
    let ctx = hello();
    let roster = rev1();
    let bootstrap = boot();
    let accept = AckSpec::new(ACCEPT_DOMAIN);
    let revoke = AckSpec::new(REVOKE_DOMAIN);

    c.valid(
        "tag-1-application",
        f,
        payload_bytes(1, &ctx.bytes()),
        json!({"tag": 1, "value": ctx.json()}),
    );
    c.valid(
        "tag-2-roster",
        f,
        payload_bytes(2, &roster.bytes()),
        json!({"tag": 2, "value": roster.json()}),
    );
    c.valid(
        "tag-3-invitation-bootstrap",
        f,
        payload_bytes(3, &bootstrap.bytes()),
        json!({"tag": 3, "value": bootstrap.json()}),
    );
    c.valid(
        "tag-4-invitation-acceptance",
        f,
        payload_bytes(4, &accept.bytes()),
        json!({"tag": 4, "value": accept.json()}),
    );
    c.valid(
        "tag-5-invitation-revocation",
        f,
        payload_bytes(5, &revoke.bytes()),
        json!({"tag": 5, "value": revoke.json()}),
    );
    c.refuse("empty-input", f, vec![], "malformed");
    c.refuse(
        "domain-only",
        f,
        b"Tacenta Group Payload v1".to_vec(),
        "malformed",
    );
    c.refuse(
        "domain-and-tag-only",
        f,
        [b"Tacenta Group Payload v1".as_slice(), &[2]].concat(),
        "malformed",
    );
    c.refuse(
        "three-length-bytes",
        f,
        [b"Tacenta Group Payload v1".as_slice(), &[2, 0, 0, 0]].concat(),
        "malformed",
    );
    c.prefixes(
        "every-proper-prefix-of-tag-2",
        f,
        payload_bytes(2, &roster.bytes()),
        "malformed",
    );
    c.prefixes(
        "every-proper-prefix-of-tag-4",
        f,
        payload_bytes(4, &accept.bytes()),
        "malformed",
    );
    let mut bad_domain = payload_bytes(2, &roster.bytes());
    bad_domain[23] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    let mut wrong_domain = payload_bytes(2, &roster.bytes());
    wrong_domain[..23].copy_from_slice(b"Tacenta Group Roster v1");
    c.refuse("domain-of-the-roster-format", f, wrong_domain, "malformed");
    for tag in [0u8, 6, 255] {
        c.refuse(
            &format!("tag-{tag}-with-a-valid-roster-value"),
            f,
            payload_bytes(tag, &roster.bytes()),
            "malformed",
        );
    }
    c.refuse(
        "tag-0-with-a-wrong-length",
        f,
        Buf::new()
            .raw(b"Tacenta Group Payload v1")
            .u8(0)
            .u32(9)
            .raw(&roster.bytes())
            .done(),
        "malformed",
    );
    let value = roster.bytes();
    for (name, delta) in [("length-one-short", -1i64), ("length-one-long", 1)] {
        let stated = u32::try_from(value.len() as i64 + delta).unwrap();
        c.refuse(
            name,
            f,
            Buf::new()
                .raw(b"Tacenta Group Payload v1")
                .u8(2)
                .u32(stated)
                .raw(&value)
                .done(),
            "malformed",
        );
    }
    let mut trailing = payload_bytes(2, &roster.bytes());
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing, "malformed");
    // A tag names the parser: the wrong bytes under a tag are refused by it.
    c.refuse(
        "tag-1-holding-a-roster",
        f,
        payload_bytes(1, &roster.bytes()),
        "malformed",
    );
    c.refuse(
        "tag-2-holding-a-context",
        f,
        payload_bytes(2, &ctx.bytes()),
        "malformed",
    );
    c.refuse(
        "tag-3-holding-an-acceptance",
        f,
        payload_bytes(3, &accept.bytes()),
        "malformed",
    );
    c.refuse(
        "tag-4-holding-a-revocation",
        f,
        payload_bytes(4, &revoke.bytes()),
        "malformed",
    );
    c.refuse(
        "tag-5-holding-an-acceptance",
        f,
        payload_bytes(5, &accept.bytes()),
        "malformed",
    );
    // The inner refusal is the payload's refusal.
    c.refuse(
        "tag-1-inner-reserved-revision",
        f,
        payload_bytes(
            1,
            &CtxSpec {
                rev: u64::MAX,
                ..ctx.clone()
            }
            .bytes(),
        ),
        "reserved_revision",
    );
    c.refuse(
        "tag-2-inner-unsorted-members",
        f,
        payload_bytes(
            2,
            &RosterSpec {
                members: vec![bob(), alice()],
                ..rev1()
            }
            .bytes(),
        ),
        "non_canonical",
    );
    c.refuse(
        "tag-3-inner-conflict",
        f,
        payload_bytes(
            3,
            &BootSpec {
                src_rev: 1,
                ..boot()
            }
            .bytes(),
        ),
        "conflict",
    );
    c.refuse(
        "tag-4-inner-reserved-revision",
        f,
        payload_bytes(
            4,
            &AckSpec {
                rev: u64::MAX,
                ..accept.clone()
            }
            .bytes(),
        ),
        "reserved_revision",
    );
    c.refuse(
        "tag-5-inner-reserved-revision",
        f,
        payload_bytes(
            5,
            &AckSpec {
                rev: u64::MAX,
                ..revoke.clone()
            }
            .bytes(),
        ),
        "reserved_revision",
    );
    c.refuse(
        "tag-1-inner-payload-1025",
        f,
        payload_bytes(
            1,
            &CtxSpec {
                payload: vec![0; 1025],
                ..ctx.clone()
            }
            .bytes(),
        ),
        "payload_too_large",
    );

    // The whole-payload bound: the inner bound decides at 8192, this one at 8193.
    let head = |tag: u8, total: usize| {
        Buf::new()
            .raw(b"Tacenta Group Payload v1")
            .u8(tag)
            .u32(u32::try_from(total - 29).unwrap())
            .done()
    };
    c.refuse_padded(
        "8192-bytes-tag-1-the-context-bound-decides",
        f,
        head(1, 8192),
        8192,
        "context_too_large",
    );
    c.refuse_padded(
        "8192-bytes-tag-2-the-roster-bound-decides",
        f,
        head(2, 8192),
        8192,
        "roster_too_large",
    );
    c.refuse_padded("8193-bytes-tag-1", f, head(1, 8193), 8193, "malformed");
    c.refuse_padded("8193-bytes-tag-2", f, head(2, 8193), 8193, "malformed");
    c.refuse_padded("8193-zero-bytes", f, vec![], 8193, "malformed");
}

fn intent_corpus(c: &mut Corpus) {
    let f = "intent";
    let i = intent();
    c.valid("one-recipient", f, i.bytes(), i.json());
    let three = IntentSpec {
        recipients: vec![bob(), carol(), m(b"dave", &[1])],
        ..intent()
    };
    c.valid("three-recipients", f, three.bytes(), three.json());
    let empty = IntentSpec {
        payload: vec![],
        rev: 0,
        seq: 0,
        ..intent()
    };
    c.valid("empty-payload-revision-0", f, empty.bytes(), empty.json());
    let top = IntentSpec {
        rev: u64::MAX - 1,
        seq: u64::MAX,
        ..intent()
    };
    c.valid("highest-revision-and-sequence", f, top.bytes(), top.json());
    let full = IntentSpec {
        payload: vec![0x5a; 1024],
        ..intent()
    };
    c.valid("payload-1024", f, full.bytes(), full.json());
    let self_send = IntentSpec {
        recipients: vec![alice(), bob()],
        ..intent()
    };
    c.valid(
        "sender-among-recipients",
        f,
        self_send.bytes(),
        self_send.json(),
    );
    let eight = IntentSpec {
        recipients: small_members(8),
        ..intent()
    };
    c.valid("eight-recipients", f, eight.bytes(), eight.json());
    let widest = IntentSpec {
        sender: m(&[0xee; 256], &[0xee; 64]),
        recipients: vec![m(&[0x01; 256], &[0x01; 64]), m(&[0x02; 256], &[0x02; 64])],
        ..intent()
    };
    c.valid(
        "sender-and-recipients-256-and-64",
        f,
        widest.bytes(),
        widest.json(),
    );
    let empty_member = IntentSpec {
        sender: m(b"", b""),
        recipients: vec![m(b"", b"x")],
        ..intent()
    };
    c.valid(
        "empty-identity-and-device",
        f,
        empty_member.bytes(),
        empty_member.json(),
    );
    let order = IntentSpec {
        recipients: vec![m(b"a", &[0xff]), m(b"ab", b"")],
        ..intent()
    };
    c.valid(
        "order-is-pair-not-concatenation",
        f,
        order.bytes(),
        order.json(),
    );

    c.refuse("empty-input", f, vec![], "malformed");
    c.prefixes("every-proper-prefix", f, three.bytes(), "malformed");
    let mut trailing = i.bytes();
    trailing.push(0);
    c.refuse("trailing-byte", f, trailing, "malformed");
    let mut bad_domain = i.bytes();
    bad_domain[28] = b'2';
    c.refuse("domain-version-changed", f, bad_domain, "malformed");
    for n in [15usize, 17] {
        c.refuse(
            &format!("group-id-{n}-bytes"),
            f,
            IntentSpec {
                group: vec![b'g'; n],
                ..i.clone()
            }
            .bytes(),
            "malformed",
        );
    }
    for n in [31usize, 33] {
        c.refuse(
            &format!("roster-digest-{n}-bytes"),
            f,
            IntentSpec {
                digest: vec![1; n],
                ..i.clone()
            }
            .bytes(),
            "malformed",
        );
    }
    let spec_payload_1025 = IntentSpec {
        payload: vec![0; 1025],
        ..i.clone()
    };
    c.refuse_both(
        "payload-1025",
        f,
        spec_payload_1025.bytes(),
        spec_payload_1025.json(),
        "payload_too_large",
    );
    let spec_no_recipients = IntentSpec {
        recipients: vec![],
        ..i.clone()
    };
    c.refuse_both(
        "no-recipients",
        f,
        spec_no_recipients.bytes(),
        spec_no_recipients.json(),
        "empty_recipients",
    );
    c.refuse(
        "nine-recipients-declared-none-present",
        f,
        IntentSpec {
            count: Some(9),
            recipients: vec![],
            ..i.clone()
        }
        .bytes(),
        "too_many_members",
    );
    let spec_nine_recipients = IntentSpec {
        recipients: small_members(9),
        ..i.clone()
    };
    c.refuse_both(
        "nine-recipients",
        f,
        spec_nine_recipients.bytes(),
        spec_nine_recipients.json(),
        "too_many_members",
    );
    c.refuse(
        "recipient-count-exceeds-recipients-present",
        f,
        IntentSpec {
            count: Some(3),
            recipients: vec![bob(), carol()],
            ..i.clone()
        }
        .bytes(),
        "malformed",
    );
    let spec_reserved_revision = IntentSpec {
        rev: u64::MAX,
        ..i.clone()
    };
    c.refuse_both(
        "reserved-revision",
        f,
        spec_reserved_revision.bytes(),
        spec_reserved_revision.json(),
        "reserved_revision",
    );
    let spec_unsorted_first_pair = IntentSpec {
        recipients: vec![carol(), bob()],
        ..i.clone()
    };
    c.refuse_both(
        "unsorted-first-pair",
        f,
        spec_unsorted_first_pair.bytes(),
        spec_unsorted_first_pair.json(),
        "non_canonical",
    );
    let mut last_swapped = small_members(8);
    last_swapped.swap(6, 7);
    let spec_unsorted_last_pair_of_eight = IntentSpec {
        recipients: last_swapped,
        ..i.clone()
    };
    c.refuse_both(
        "unsorted-last-pair-of-eight",
        f,
        spec_unsorted_last_pair_of_eight.bytes(),
        spec_unsorted_last_pair_of_eight.json(),
        "non_canonical",
    );
    let spec_duplicate_recipient = IntentSpec {
        recipients: vec![bob(), bob()],
        ..i.clone()
    };
    c.refuse_both(
        "duplicate-recipient",
        f,
        spec_duplicate_recipient.bytes(),
        spec_duplicate_recipient.json(),
        "non_canonical",
    );
    let spec_same_identity_second_device = IntentSpec {
        recipients: vec![bob(), m(b"bob", &[2])],
        ..i.clone()
    };
    c.refuse_both(
        "same-identity-second-device",
        f,
        spec_same_identity_second_device.bytes(),
        spec_same_identity_second_device.json(),
        "non_canonical",
    );
    let mut last_second_device = small_members(7);
    last_second_device.push(m(&[b'm', 7], &[2]));
    let spec_last_pair_second_device = IntentSpec {
        recipients: last_second_device,
        ..i.clone()
    };
    c.refuse_both(
        "same-identity-second-device-at-the-last-pair-of-eight",
        f,
        spec_last_pair_second_device.bytes(),
        spec_last_pair_second_device.json(),
        "non_canonical",
    );
    let spec_concatenation_order_is_refused = IntentSpec {
        recipients: vec![m(b"ab", b""), m(b"a", &[0xff])],
        ..i.clone()
    };
    c.refuse_both(
        "concatenation-order-is-refused",
        f,
        spec_concatenation_order_is_refused.bytes(),
        spec_concatenation_order_is_refused.json(),
        "non_canonical",
    );
    let spec_sender_identity_257 = IntentSpec {
        sender: m(&vec![9; 257], &[1]),
        ..i.clone()
    };
    c.refuse_both(
        "sender-identity-257",
        f,
        spec_sender_identity_257.bytes(),
        spec_sender_identity_257.json(),
        "identity_too_large",
    );
    let spec_sender_device_65 = IntentSpec {
        sender: m(b"s", &[9; 65]),
        ..i.clone()
    };
    c.refuse_both(
        "sender-device-65",
        f,
        spec_sender_device_65.bytes(),
        spec_sender_device_65.json(),
        "device_too_large",
    );
    let mut wide_last = small_members(7);
    wide_last.push(m(&vec![0xff; 257], &[1]));
    let spec_last_recipient_identity_257 = IntentSpec {
        recipients: wide_last,
        ..i.clone()
    };
    c.refuse_both(
        "recipient-identity-257-at-the-last-of-eight",
        f,
        spec_last_recipient_identity_257.bytes(),
        spec_last_recipient_identity_257.json(),
        "identity_too_large",
    );
    let spec_recipient_device_65_first = IntentSpec {
        recipients: vec![m(b"b", &[9; 65])],
        ..i.clone()
    };
    c.refuse_both(
        "recipient-device-65-first",
        f,
        spec_recipient_device_65_first.bytes(),
        spec_recipient_device_65_first.json(),
        "device_too_large",
    );
    // Precedence (section 11, steps 10 to 12).
    let mut reserved_trailing = IntentSpec {
        rev: u64::MAX,
        ..i.clone()
    }
    .bytes();
    reserved_trailing.push(0);
    c.refuse(
        "precedence-trailing-byte-before-reserved-revision",
        f,
        reserved_trailing,
        "malformed",
    );
    c.refuse(
        "precedence-order-before-reserved-revision",
        f,
        IntentSpec {
            rev: u64::MAX,
            recipients: vec![carol(), bob()],
            ..i.clone()
        }
        .bytes(),
        "non_canonical",
    );
    c.refuse(
        "precedence-payload-size-before-recipient-count",
        f,
        IntentSpec {
            payload: vec![0; 1025],
            recipients: vec![],
            ..i.clone()
        }
        .bytes(),
        "payload_too_large",
    );
}

/// Vectors added after the second reader's fault run showed which rules the
/// first corpus did not fail on: list entries away from the ends, partly zero
/// predecessor digests, the order of two faults where the page states it, and
/// the bootstrap encoder's own checks.
fn roster_more(c: &mut Corpus) {
    let f = "roster";
    let r1 = rev1();

    // Duplicate identity and order away from the last pair.
    let dup_first = RosterSpec {
        members: vec![alice(), m(b"alice", &[2]), bob()],
        ..r1.clone()
    };
    c.refuse(
        "same-identity-second-device-at-the-first-pair-of-three",
        f,
        dup_first.bytes(),
        "non_canonical",
    );
    c.encode_refuse(
        "same-identity-second-device-at-the-first-pair-of-three",
        f,
        dup_first.json(),
        "non_canonical",
    );
    let mut middle = small_members(4);
    middle.swap(1, 2);
    let unsorted_middle = roster_of(middle);
    c.refuse(
        "unsorted-middle-pair-of-four",
        f,
        unsorted_middle.bytes(),
        "non_canonical",
    );
    c.encode_refuse(
        "unsorted-middle-pair-of-four",
        f,
        unsorted_middle.json(),
        "non_canonical",
    );

    // A predecessor digest that is zero except for one byte.
    for (label, at) in [("first-byte", 0usize), ("last-byte", 31)] {
        let mut pred = vec![0u8; 32];
        pred[at] = 1;
        let bad = RosterSpec { pred, ..genesis() };
        c.refuse(
            &format!("genesis-predecessor-differs-in-the-{label}"),
            f,
            bad.bytes(),
            "invalid_genesis",
        );
    }

    // Size faults at the last of eight also stop the encoder.
    let mut wide_last = small_members(7);
    wide_last.push(m(&[0xff; 257], &[1]));
    let wide_last = roster_of(wide_last);
    c.encode_refuse(
        "identity-257-in-last-of-eight",
        f,
        wide_last.json(),
        "identity_too_large",
    );
    let mut dev_last = small_members(7);
    dev_last.push(m(&[b'n', 1], &[0xff; 65]));
    let dev_last = roster_of(dev_last);
    c.encode_refuse(
        "device-65-in-last-of-eight",
        f,
        dev_last.json(),
        "device_too_large",
    );

    // Precedence: genesis before order; a size at read time before trailing bytes.
    let genesis_and_order = RosterSpec {
        members: vec![bob(), alice()],
        ..genesis()
    };
    c.refuse(
        "precedence-genesis-before-order",
        f,
        genesis_and_order.bytes(),
        "invalid_genesis",
    );
    c.encode_refuse(
        "precedence-genesis-before-order",
        f,
        genesis_and_order.json(),
        "invalid_genesis",
    );
    let with_trailing = |spec: &RosterSpec| {
        let mut bytes = spec.bytes();
        bytes.push(0);
        bytes
    };
    let authority_wide = RosterSpec {
        authority: m(&[9; 257], &[1]),
        ..r1.clone()
    };
    let first_wide = RosterSpec {
        members: vec![m(&[9; 257], &[1]), bob()],
        ..r1.clone()
    };
    let mut last_members = small_members(7);
    last_members.push(m(&[0xff; 257], &[1]));
    let last_wide = roster_of(last_members);
    let authority_dev = RosterSpec {
        authority: m(b"a", &[9; 65]),
        ..r1.clone()
    };
    let first_dev = RosterSpec {
        members: vec![m(b"a", &[9; 65]), bob()],
        ..r1.clone()
    };
    let mut last_dev_members = small_members(7);
    last_dev_members.push(m(&[b'n', 1], &[0xff; 65]));
    let last_dev = roster_of(last_dev_members);
    for (label, spec, reason) in [
        ("authority-identity", &authority_wide, "identity_too_large"),
        ("first-member-identity", &first_wide, "identity_too_large"),
        ("last-member-identity", &last_wide, "identity_too_large"),
        ("authority-device", &authority_dev, "device_too_large"),
        ("first-member-device", &first_dev, "device_too_large"),
        ("last-member-device", &last_dev, "device_too_large"),
    ] {
        c.refuse(
            &format!("precedence-{label}-size-at-read-before-trailing-byte"),
            f,
            with_trailing(spec),
            reason,
        );
    }
}

fn context_more(c: &mut Corpus) {
    let f = "context";
    let h = hello();
    let mut trailing_reserved = CtxSpec {
        rev: u64::MAX,
        ..h.clone()
    }
    .bytes();
    trailing_reserved.push(0);
    c.refuse(
        "precedence-trailing-byte-before-reserved-revision",
        f,
        trailing_reserved,
        "malformed",
    );
    // A member's size is refused when it is read, before the payload is judged.
    for (label, sender, recipient, reason) in [
        (
            "sender-device",
            m(b"s", &[9; 65]),
            bob(),
            "device_too_large",
        ),
        (
            "recipient-identity",
            alice(),
            m(&[9; 257], &[1]),
            "identity_too_large",
        ),
        (
            "recipient-device",
            alice(),
            m(b"r", &[9; 65]),
            "device_too_large",
        ),
    ] {
        let spec = CtxSpec {
            sender,
            recipient,
            payload: vec![0; 1025],
            ..h.clone()
        };
        c.refuse(
            &format!("precedence-{label}-size-at-read-before-payload-size"),
            f,
            spec.bytes(),
            reason,
        );
    }
    let both = CtxSpec {
        sender: m(&[9; 257], &[1]),
        recipient: m(b"r", &[9; 65]),
        ..h.clone()
    };
    c.refuse_both(
        "precedence-sender-size-before-recipient-size",
        f,
        both.bytes(),
        both.json(),
        "identity_too_large",
    );
    let recipient_only = CtxSpec {
        recipient: m(b"r", &[9; 65]),
        ..h.clone()
    };
    c.refuse_both(
        "recipient-device-65-after-a-valid-sender",
        f,
        recipient_only.bytes(),
        recipient_only.json(),
        "device_too_large",
    );
}

fn bootstrap_more(c: &mut Corpus) {
    let f = "bootstrap";
    let closed_source = BootSpec {
        src_rev: 2,
        src_digest: fill(0x22),
        roster: RosterSpec {
            rev: 2,
            closed: 1,
            ..rev1()
        },
        ..boot()
    };
    c.valid(
        "closed-source-roster",
        f,
        closed_source.bytes(),
        closed_source.json(),
    );

    // The encoder makes the decoder's checks in the decoder's order (section 7,
    // Encoding), so a value with several faults is refused with the same reason
    // by both, and the precedence vectors come in pairs. `refuse_both` writes
    // the pair; the decoder-only ones (trailing bytes) have no fields to state.
    let unsorted_roster = || RosterSpec {
        members: vec![bob(), alice()],
        ..rev1()
    };
    let conflict_and_bad_roster = BootSpec {
        group: vec![b'x'; 16],
        roster: unsorted_roster(),
        src_rev: 1,
        ..boot()
    };
    c.refuse_both(
        "precedence-embedded-roster-before-conflict",
        f,
        conflict_and_bad_roster.bytes(),
        conflict_and_bad_roster.json(),
        "non_canonical",
    );
    let bad_roster = BootSpec {
        src_rev: 1,
        roster: unsorted_roster(),
        ..boot()
    };
    c.encode_refuse(
        "embedded-roster-unsorted",
        f,
        bad_roster.json(),
        "non_canonical",
    );

    // Precedence (section 7, steps 8 to 11).
    let mut roster_and_trailing = bad_roster.bytes();
    roster_and_trailing.push(0);
    c.refuse(
        "precedence-embedded-roster-before-trailing-byte",
        f,
        roster_and_trailing,
        "non_canonical",
    );
    let roster_and_target = BootSpec {
        target: m(&[1; 257], &[1]),
        src_rev: 1,
        roster: unsorted_roster(),
        ..boot()
    };
    c.refuse_both(
        "precedence-embedded-roster-before-target-size",
        f,
        roster_and_target.bytes(),
        roster_and_target.json(),
        "non_canonical",
    );
    let reserved_and_policy = BootSpec {
        src_rev: u64::MAX,
        policy: 2,
        ..boot()
    };
    c.refuse_both(
        "precedence-reserved-source-revision-before-policy",
        f,
        reserved_and_policy.bytes(),
        reserved_and_policy.json(),
        "reserved_revision",
    );
    let policy_and_target = BootSpec {
        policy: 2,
        target: m(&[1; 257], &[1]),
        ..boot()
    };
    c.refuse_both(
        "precedence-policy-before-target-size",
        f,
        policy_and_target.bytes(),
        policy_and_target.json(),
        "unsupported_policy",
    );
    let identity_and_device = BootSpec {
        target: m(&[1; 257], &[1; 65]),
        ..boot()
    };
    c.refuse_both(
        "precedence-target-identity-size-before-device-size",
        f,
        identity_and_device.bytes(),
        identity_and_device.json(),
        "identity_too_large",
    );
}

fn intent_more(c: &mut Corpus) {
    let f = "intent";
    let i = intent();
    let dup_first = IntentSpec {
        recipients: vec![bob(), m(b"bob", &[2]), carol()],
        ..i.clone()
    };
    c.refuse(
        "same-identity-second-device-at-the-first-pair-of-three",
        f,
        dup_first.bytes(),
        "non_canonical",
    );
    let mut middle = small_members(4);
    middle.swap(1, 2);
    c.refuse(
        "unsorted-middle-pair-of-four",
        f,
        IntentSpec {
            recipients: middle,
            ..i.clone()
        }
        .bytes(),
        "non_canonical",
    );
    let mut first_of_three = small_members(3);
    first_of_three.swap(0, 1);
    c.refuse(
        "unsorted-first-pair-of-three",
        f,
        IntentSpec {
            recipients: first_of_three,
            ..i.clone()
        }
        .bytes(),
        "non_canonical",
    );
    c.refuse(
        "recipient-identity-257-at-the-first-of-three",
        f,
        IntentSpec {
            recipients: vec![m(&[1; 257], &[1]), m(&[2], &[1]), m(&[3], &[1])],
            ..i.clone()
        }
        .bytes(),
        "identity_too_large",
    );
    c.refuse(
        "recipient-device-65-in-the-middle-of-three",
        f,
        IntentSpec {
            recipients: vec![m(&[1], &[1]), m(&[2], &[9; 65]), m(&[3], &[1])],
            ..i.clone()
        }
        .bytes(),
        "device_too_large",
    );
    let mut unsorted_trailing = IntentSpec {
        recipients: vec![carol(), bob()],
        ..i.clone()
    }
    .bytes();
    unsorted_trailing.push(0);
    c.refuse(
        "precedence-trailing-byte-before-order",
        f,
        unsorted_trailing,
        "malformed",
    );
}

fn corpus() -> Vec<Vector> {
    let mut c = Corpus::default();
    roster_corpus(&mut c);
    roster_more(&mut c);
    context_corpus(&mut c);
    context_more(&mut c);
    bootstrap_corpus(&mut c);
    bootstrap_more(&mut c);
    ack_corpus(&mut c, ACCEPT_DOMAIN, "acceptance", REVOKE_DOMAIN);
    ack_corpus(&mut c, REVOKE_DOMAIN, "revocation", ACCEPT_DOMAIN);
    payload_corpus(&mut c);
    intent_corpus(&mut c);
    intent_more(&mut c);
    c.0
}

/// Commitments over vector inputs, with digests computed by SHA-256 over the
/// label of section 13 (`tacenta-core` checks the same entries against its own
/// functions).
fn commitments() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    vec![
        ("roster", genesis().bytes(), D_GENESIS),
        ("roster", rev1().bytes(), D_REV1),
        ("payload", hello().bytes(), D_HELLO),
    ]
}

fn render() -> String {
    let mut out = String::new();
    out.push_str("{\n  \"format\": \"group-wire-v1\",\n");
    out.push_str(&format!(
        "  \"limits\": {{\"group_id_len\": {GROUP_ID_LEN}, \"invitation_id_len\": 16, \"digest_len\": {DIGEST_LEN}, \"max_members\": 8, \"max_identity_len\": 256, \"max_device_len\": 64, \"max_payload_len\": 1024, \"max_roster_len\": 4096, \"max_context_len\": 2048, \"max_group_payload_len\": 8192, \"policy_version\": 1, \"reserved_revision\": \"18446744073709551615\"}},\n"
    ));
    out.push_str("  \"domains\": {\"roster\": \"Tacenta Group Roster v1\", \"context\": \"Tacenta Group Application v1\", \"bootstrap\": \"Tacenta Group Invitation Bootstrap v1\", \"acceptance\": \"Tacenta Group Invitation Acceptance v1\", \"revocation\": \"Tacenta Group Invitation Revocation v1\", \"payload\": \"Tacenta Group Payload v1\", \"intent\": \"Tacenta Group Logical Send v1\"},\n");
    out.push_str("  \"commitments\": [\n");
    let commits = commitments();
    for (index, (kind, preimage, digest)) in commits.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"kind\": \"{kind}\", \"preimage\": \"{}\", \"digest\": \"{digest}\"}}{}\n",
            hex(preimage),
            if index + 1 == commits.len() { "" } else { "," }
        ));
    }
    out.push_str("  ],\n  \"vectors\": [\n");
    let vectors = corpus();
    for (index, vector) in vectors.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&vector.line());
        out.push_str(if index + 1 == vectors.len() {
            "\n"
        } else {
            ",\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}

// ---------------------------------------------------------------------------
// The production side: the committed file against the shipped codecs.
// ---------------------------------------------------------------------------

fn label(error: &Error) -> String {
    match error {
        Error::Malformed => "malformed",
        Error::NonCanonical => "non_canonical",
        Error::UnsupportedPolicy => "unsupported_policy",
        Error::ReservedRevision => "reserved_revision",
        Error::InvalidGenesis => "invalid_genesis",
        Error::TooManyMembers => "too_many_members",
        Error::PayloadTooLarge => "payload_too_large",
        Error::IdentityTooLarge => "identity_too_large",
        Error::DeviceTooLarge => "device_too_large",
        Error::RosterTooLarge => "roster_too_large",
        Error::ContextTooLarge => "context_too_large",
        Error::Conflict => "conflict",
        Error::EmptyRecipients => "empty_recipients",
        other => return format!("unexpected:{other:?}"),
    }
    .to_string()
}

fn member_value(member: &Member) -> Value {
    json!({"identity": hex(member.identity()), "device": hex(member.device())})
}

fn roster_value(r: &Roster) -> Value {
    json!({
        "group_id": hex(r.group_id.as_bytes()),
        "revision": r.revision.to_string(),
        "predecessor_digest": hex(&r.predecessor_digest),
        "authority": member_value(&r.authority),
        "policy_version": r.policy_version,
        "closed": r.closed,
        "members": r.members.iter().map(member_value).collect::<Vec<_>>(),
    })
}

fn context_value(x: &ApplicationContext) -> Value {
    json!({
        "group_id": hex(x.group_id.as_bytes()),
        "revision": x.revision.to_string(),
        "roster_digest": hex(&x.roster_digest),
        "sender": member_value(&x.sender),
        "recipient": member_value(&x.recipient),
        "logical_sequence": x.logical_sequence.to_string(),
        "payload": hex(&x.payload),
    })
}

fn bootstrap_value(b: &InvitationBootstrap) -> Value {
    let i = &b.invitation;
    json!({
        "invitation_id": hex(i.id.as_bytes()),
        "group_id": hex(i.group_id.as_bytes()),
        "target": member_value(&i.target),
        "source_revision": i.source_revision.to_string(),
        "source_roster_digest": hex(&i.source_roster_digest),
        "policy_version": i.policy_version,
        "expires_at": i.expires_at.to_string(),
        "source_roster": roster_value(&b.source_roster),
    })
}

fn acceptance_value(a: &InvitationAcceptance) -> Value {
    json!({
        "group_id": hex(a.group_id.as_bytes()),
        "invitation_id": hex(a.invitation_id.as_bytes()),
        "source_revision": a.source_revision.to_string(),
        "source_roster_digest": hex(&a.source_roster_digest),
    })
}

fn revocation_value(a: &InvitationRevocation) -> Value {
    json!({
        "group_id": hex(a.group_id.as_bytes()),
        "invitation_id": hex(a.invitation_id.as_bytes()),
        "source_revision": a.source_revision.to_string(),
        "source_roster_digest": hex(&a.source_roster_digest),
    })
}

fn intent_value(s: &LogicalSend) -> Value {
    json!({
        "group_id": hex(s.id.group_id.as_bytes()),
        "revision": s.id.revision.to_string(),
        "sender": member_value(&s.id.sender),
        "sequence": s.id.sequence.to_string(),
        "roster_digest": hex(&s.roster_digest),
        "payload": hex(&s.payload),
        "recipients": s.recipients().iter().map(|p| member_value(&p.recipient)).collect::<Vec<_>>(),
    })
}

fn payload_value(p: &GroupPayload) -> Value {
    match p {
        GroupPayload::Application(x) => json!({"tag": 1, "value": context_value(x)}),
        GroupPayload::Roster(x) => json!({"tag": 2, "value": roster_value(x)}),
        GroupPayload::InvitationBootstrap(x) => json!({"tag": 3, "value": bootstrap_value(x)}),
        GroupPayload::InvitationAcceptance(x) => json!({"tag": 4, "value": acceptance_value(x)}),
        GroupPayload::InvitationRevocation(x) => json!({"tag": 5, "value": revocation_value(x)}),
    }
}

fn decode(format: &str, bytes: &[u8]) -> Result<Value, String> {
    match format {
        "roster" => Roster::decode(bytes).map(|x| roster_value(&x)),
        "context" => ApplicationContext::decode(bytes).map(|x| context_value(&x)),
        "bootstrap" => InvitationBootstrap::decode(bytes).map(|x| bootstrap_value(&x)),
        "acceptance" => InvitationAcceptance::decode(bytes).map(|x| acceptance_value(&x)),
        "revocation" => InvitationRevocation::decode(bytes).map(|x| revocation_value(&x)),
        "payload" => GroupPayload::decode(bytes).map(|x| payload_value(&x)),
        "intent" => LogicalSend::decode_intent(bytes).map(|x| intent_value(&x)),
        other => panic!("unknown format {other}"),
    }
    .map_err(|e| label(&e))
}

fn field_hex(v: &Value, key: &str) -> Vec<u8> {
    unhex(v[key].as_str().unwrap_or_else(|| panic!("{key}")))
}

fn field_u64(v: &Value, key: &str) -> u64 {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key}"))
        .parse()
        .expect("u64")
}

fn field_u32(v: &Value, key: &str) -> u32 {
    u32::try_from(v[key].as_u64().unwrap_or_else(|| panic!("{key}"))).expect("u32")
}

fn member_from(v: &Value) -> Member {
    Member::new(field_hex(v, "identity"), field_hex(v, "device"))
}

fn group_from(v: &Value) -> GroupId {
    GroupId::new(field_hex(v, "group_id").try_into().expect("group id"))
}

fn digest_from(v: &Value, key: &str) -> [u8; DIGEST_LEN] {
    field_hex(v, key).try_into().expect("digest")
}

fn roster_from(v: &Value) -> Roster {
    Roster {
        group_id: group_from(v),
        revision: field_u64(v, "revision"),
        predecessor_digest: digest_from(v, "predecessor_digest"),
        authority: member_from(&v["authority"]),
        policy_version: field_u32(v, "policy_version"),
        closed: v["closed"].as_bool().expect("closed"),
        members: v["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(member_from)
            .collect(),
    }
}

fn context_from(v: &Value) -> ApplicationContext {
    ApplicationContext {
        group_id: group_from(v),
        revision: field_u64(v, "revision"),
        roster_digest: digest_from(v, "roster_digest"),
        sender: member_from(&v["sender"]),
        recipient: member_from(&v["recipient"]),
        logical_sequence: field_u64(v, "logical_sequence"),
        payload: field_hex(v, "payload"),
    }
}

fn bootstrap_from(v: &Value) -> InvitationBootstrap {
    InvitationBootstrap {
        invitation: Invitation {
            id: InvitationId::new(field_hex(v, "invitation_id").try_into().expect("id")),
            group_id: group_from(v),
            target: member_from(&v["target"]),
            source_revision: field_u64(v, "source_revision"),
            source_roster_digest: digest_from(v, "source_roster_digest"),
            policy_version: field_u32(v, "policy_version"),
            expires_at: field_u64(v, "expires_at"),
            status: InvitationStatus::Pending,
        },
        source_roster: roster_from(&v["source_roster"]),
    }
}

fn acceptance_from(v: &Value) -> InvitationAcceptance {
    InvitationAcceptance {
        group_id: group_from(v),
        invitation_id: InvitationId::new(field_hex(v, "invitation_id").try_into().expect("id")),
        source_revision: field_u64(v, "source_revision"),
        source_roster_digest: digest_from(v, "source_roster_digest"),
    }
}

fn revocation_from(v: &Value) -> InvitationRevocation {
    InvitationRevocation {
        group_id: group_from(v),
        invitation_id: InvitationId::new(field_hex(v, "invitation_id").try_into().expect("id")),
        source_revision: field_u64(v, "source_revision"),
        source_roster_digest: digest_from(v, "source_roster_digest"),
    }
}

/// The roster a logical send is built from: open, listing the sender and the
/// recipients. `LogicalSend::new` reads only these fields of it.
fn intent_roster(v: &Value, sender: &Member, recipients: &[Member]) -> Roster {
    let mut members = vec![sender.clone()];
    members.extend(recipients.iter().filter(|r| *r != sender).cloned());
    Roster {
        group_id: group_from(v),
        revision: field_u64(v, "revision"),
        predecessor_digest: [0; DIGEST_LEN],
        authority: sender.clone(),
        policy_version: POLICY_VERSION_V1,
        closed: false,
        members,
    }
}

fn encode(format: &str, fields: &Value) -> Result<Vec<u8>, String> {
    match format {
        "roster" => roster_from(fields).encode(),
        "context" => context_from(fields).encode(),
        "bootstrap" => bootstrap_from(fields).encode(),
        "acceptance" => acceptance_from(fields).encode(),
        "revocation" => revocation_from(fields).encode(),
        "payload" => {
            let value = &fields["value"];
            let payload = match fields["tag"].as_u64().expect("tag") {
                1 => GroupPayload::Application(context_from(value)),
                2 => GroupPayload::Roster(roster_from(value)),
                3 => GroupPayload::InvitationBootstrap(bootstrap_from(value)),
                4 => GroupPayload::InvitationAcceptance(acceptance_from(value)),
                5 => GroupPayload::InvitationRevocation(revocation_from(value)),
                other => panic!("tag {other}"),
            };
            payload.encode()
        }
        "intent" => {
            let sender = member_from(&fields["sender"]);
            let recipients: Vec<Member> = fields["recipients"]
                .as_array()
                .expect("recipients")
                .iter()
                .map(member_from)
                .collect();
            let roster = intent_roster(fields, &sender, &recipients);
            LogicalSend::new(
                &roster,
                digest_from(fields, "roster_digest"),
                sender,
                field_u64(fields, "sequence"),
                recipients,
                field_hex(fields, "payload"),
            )
            .and_then(|send| send.encode_intent())
        }
        other => panic!("unknown format {other}"),
    }
    .map_err(|e| label(&e))
}

fn vector_bytes(vector: &Value) -> Vec<u8> {
    let mut bytes = unhex(vector["bytes"].as_str().expect("bytes"));
    if let Some(total) = vector.get("pad_to") {
        let total = usize::try_from(total.as_u64().expect("pad_to")).expect("usize");
        assert!(bytes.len() <= total, "pad_to below the prefix");
        bytes.resize(total, 0);
    }
    bytes
}

fn replay(vector: &Value) -> Result<(), String> {
    let format = vector["format"].as_str().expect("format");
    match vector["result"].as_str().expect("result") {
        "valid" => {
            let bytes = vector_bytes(vector);
            let decoded = decode(format, &bytes)?;
            if decoded != vector["fields"] {
                return Err(format!("decoded {decoded}, expected {}", vector["fields"]));
            }
            let encoded = encode(format, &vector["fields"])?;
            if encoded != bytes {
                return Err(format!(
                    "encoded {}, expected {}",
                    hex(&encoded),
                    hex(&bytes)
                ));
            }
            Ok(())
        }
        "refuse" => {
            let reason = vector["reason"].as_str().expect("reason");
            match decode(format, &vector_bytes(vector)) {
                Err(got) if got == reason => Ok(()),
                Err(got) => Err(format!("refused with {got}, expected {reason}")),
                Ok(value) => Err(format!("accepted {value}, expected {reason}")),
            }
        }
        "refuse_prefixes" => {
            let reason = vector["reason"].as_str().expect("reason");
            let bytes = vector_bytes(vector);
            for length in 0..bytes.len() {
                match decode(format, &bytes[..length]) {
                    Err(got) if got == reason => {}
                    Err(got) => {
                        return Err(format!(
                            "prefix of {length} bytes refused with {got}, expected {reason}"
                        ));
                    }
                    Ok(_) => return Err(format!("prefix of {length} bytes was accepted")),
                }
            }
            Ok(())
        }
        "encode_refuse" => {
            let reason = vector["reason"].as_str().expect("reason");
            match encode(format, &vector["fields"]) {
                Err(got) if got == reason => Ok(()),
                Err(got) => Err(format!("encoder refused with {got}, expected {reason}")),
                Ok(bytes) => Err(format!(
                    "encoder produced {}, expected {reason}",
                    hex(&bytes)
                )),
            }
        }
        other => panic!("unknown result {other}"),
    }
}

fn committed() -> Value {
    let text = std::fs::read_to_string(FILE).expect("contracts/vectors/group-wire-v1.json");
    serde_json::from_str(&text).expect("valid JSON")
}

#[test]
fn committed_vectors_are_current() {
    let rendered = render();
    if std::env::var_os(WRITE_ENV).is_some() {
        std::fs::write(FILE, &rendered).expect("write the vector file");
        return;
    }
    let on_disk = std::fs::read_to_string(FILE).expect("contracts/vectors/group-wire-v1.json");
    // A checkout that converts line endings must not fail the comparison.
    let on_disk = on_disk.replace("\r\n", "\n");
    assert!(
        on_disk == rendered,
        "contracts/vectors/group-wire-v1.json differs from the builder in this test; \
         rerun with {WRITE_ENV}=1 and review the diff"
    );
}

#[test]
fn production_codecs_replay_every_committed_vector() {
    let doc = committed();
    assert_eq!(doc["format"], "group-wire-v1");
    let vectors = doc["vectors"].as_array().expect("vectors");
    let mut failures = Vec::new();
    for vector in vectors {
        if let Err(problem) = replay(vector) {
            failures.push(format!("{}: {problem}", vector["name"]));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} vectors fail:\n{}",
        failures.len(),
        vectors.len(),
        failures.join("\n")
    );
}

/// The one encoder refusal whose order the page says differs from the decoder's
/// (section 6: the payload is judged before the members' sizes).
const ENCODER_ONLY_ORDER: [&str; 1] =
    ["context/encode-precedence-encode-checks-payload-before-sender-size"];

/// An encoder must not write what its own decoder refuses (section 3 of the
/// page, and the fix of open point 4). Every encoder refusal in the file is
/// therefore paired with the decoder's refusal of the same fault, under the same
/// name without `encode-`, with the same reason, so that an encoder that checks
/// less than its decoder shows up as a decoder refusal with no encoder twin the
/// next time someone adds it. The pairing is not an exhaustive proof: it holds
/// the faults the file states.
#[test]
fn every_encoder_refusal_has_a_decoder_twin() {
    let doc = committed();
    let vectors = doc["vectors"].as_array().expect("vectors");
    let by_name: std::collections::BTreeMap<&str, &Value> = vectors
        .iter()
        .map(|v| (v["name"].as_str().expect("name"), v))
        .collect();
    let mut problems = Vec::new();
    for vector in vectors.iter().filter(|v| v["result"] == "encode_refuse") {
        let name = vector["name"].as_str().expect("name");
        if ENCODER_ONLY_ORDER.contains(&name) {
            continue;
        }
        let twin_name = name.replacen("/encode-", "/", 1);
        match by_name.get(twin_name.as_str()) {
            None => problems.push(format!("{name}: no decoder vector {twin_name}")),
            Some(twin) if twin["result"] != "refuse" => {
                problems.push(format!("{name}: {twin_name} is not a refusal"));
            }
            Some(twin) if twin["reason"] != vector["reason"] => problems.push(format!(
                "{name}: the encoder gives {}, the decoder {}",
                vector["reason"], twin["reason"]
            )),
            Some(_) => {}
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_file_states_the_constants_the_crate_exports() {
    let doc = committed();
    let limits = &doc["limits"];
    assert_eq!(limits["group_id_len"], 16);
    assert_eq!(limits["invitation_id_len"], 16);
    assert_eq!(limits["digest_len"], 32);
    assert_eq!(limits["max_members"], 8);
    assert_eq!(limits["max_identity_len"], 256);
    assert_eq!(limits["max_device_len"], 64);
    assert_eq!(limits["max_payload_len"], 1024);
    assert_eq!(limits["max_roster_len"], 4096);
    assert_eq!(limits["max_context_len"], 2048);
    assert_eq!(limits["max_group_payload_len"], 8192);
    assert_eq!(limits["policy_version"], 1);
    assert_eq!(limits["reserved_revision"], "18446744073709551615");
    assert_eq!(GROUP_ID_LEN, 16);
    assert_eq!(DIGEST_LEN, 32);
    assert_eq!(MAX_MEMBERS, 8);
    assert_eq!(MAX_IDENTITY_LEN, 256);
    assert_eq!(MAX_DEVICE_LEN, 64);
    assert_eq!(MAX_PAYLOAD_LEN, 1024);
    assert_eq!(MAX_ROSTER_LEN, 4096);
    assert_eq!(MAX_APPLICATION_CONTEXT_LEN, 2048);
    assert_eq!(POLICY_VERSION_V1, 1);
    assert_eq!(RESERVED_REVISION, u64::MAX);
}

#[test]
fn the_file_covers_every_format_result_reason_and_tag() {
    let doc = committed();
    let vectors = doc["vectors"].as_array().expect("vectors");
    let mut names = BTreeSet::new();
    let mut formats = BTreeSet::new();
    let mut results = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for vector in vectors {
        assert!(
            names.insert(vector["name"].as_str().expect("name")),
            "duplicate vector name {}",
            vector["name"]
        );
        formats.insert(vector["format"].as_str().expect("format"));
        results.insert(vector["result"].as_str().expect("result"));
        if let Some(reason) = vector.get("reason") {
            reasons.insert(reason.as_str().expect("reason"));
        }
        if vector["format"] == "payload" && vector["result"] == "valid" {
            tags.insert(vector["fields"]["tag"].as_u64().expect("tag"));
        }
    }
    assert_eq!(
        formats.into_iter().collect::<Vec<_>>(),
        [
            "acceptance",
            "bootstrap",
            "context",
            "intent",
            "payload",
            "revocation",
            "roster"
        ]
    );
    assert_eq!(
        results.into_iter().collect::<Vec<_>>(),
        ["encode_refuse", "refuse", "refuse_prefixes", "valid"]
    );
    assert_eq!(
        reasons.into_iter().collect::<Vec<_>>(),
        [
            "conflict",
            "context_too_large",
            "device_too_large",
            "empty_recipients",
            "identity_too_large",
            "invalid_genesis",
            "malformed",
            "non_canonical",
            "payload_too_large",
            "reserved_revision",
            "roster_too_large",
            "too_many_members",
            "unsupported_policy"
        ]
    );
    assert_eq!(tags.into_iter().collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
}
