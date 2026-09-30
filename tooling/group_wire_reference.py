#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reference reader for the bounded group-chat wire formats, version 1.

A differential oracle for ``spec/group-wire-formats.md`` (section numbers below
refer to that page), not an independent implementation of it.  It was first
written by a separate agent from the page and the vector file, after that agent
had printed the name and expected reason of every vector then in the file; the
file was then edited, and the bootstrap and intent encoders were revised by the
implementer of the encoder change, not by a fresh reader (open point 4).
Section 14 of the page, "What the second reader is, and is not", says the same.
Each rule line carries a bracketed id, for example ``[RD3]`` (roster decode step
3) or ``[RV6b]`` (V-roster step 6, second clause), and a comment naming the
sentence of the text it comes from.

Public API
    Refusal              exception with a ``.reason`` label (section 3)
    EncoderInputError    ValueError: an encoder was handed something that is not
                         a value of the page's types (see below); not a refusal
    decode(fmt, data)    bytes -> field dictionary in the JSON shape of section 14
    encode(fmt, fields)  field dictionary -> bytes
    roster_commitment(preimage), payload_commitment(context)   section 13
    LIMITS, DOMAINS      the constants of section 2 and the domain strings, under
                         the keys section 14 gives them in the vector file

Encoders (section 3, "Encoders"): an encoder is given values of the page's types
(fixed fields of their fixed length, integers within their width, a payload tag
from 1 to 5); "what an encoder does with anything else is outside this page".
This module raises EncoderInputError for such input rather than inventing a
refusal reason, and Refusal only for the refusals that the "Encoding" paragraph
of each section lists.

Python 3.8 or later, standard library only.
"""

import hashlib
import re

# ---------------------------------------------------------------------------
# Section 3: refusals
# ---------------------------------------------------------------------------


class Refusal(Exception):
    """A decoder or encoder refusal; ``reason`` is one of the section 3 labels."""

    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


class EncoderInputError(ValueError):
    """Encoder input that is not a value of the page's types (section 3, "Encoders")."""


# ---------------------------------------------------------------------------
# Section 2: constants
# ---------------------------------------------------------------------------

GROUP_ID_LEN = 16          # "group ID length 16"
INVITATION_ID_LEN = 16     # "invitation ID length 16"
DIGEST_LEN = 32            # "digest length 32"
POLICY_VERSION = 1         # "policy version 1 ... carried as a u32"
MAX_MEMBERS = 8            # "maximum members 8"
MAX_IDENTITY = 256         # "maximum identity length 256"
MAX_DEVICE = 64            # "maximum device length 64"
MAX_PAYLOAD = 1024         # "maximum application payload 1,024"
MAX_ROSTER = 4096          # "maximum roster length 4,096"
MAX_CONTEXT = 2048         # "maximum context length 2,048"
MAX_GROUP_PAYLOAD = 8192   # "maximum group payload length 8,192"
RESERVED_REVISION = 2 ** 64 - 1   # section 1 "Revision" / section 2

# Domain strings (table at the top of the page; lengths from sections 5-11).
DOM_ROSTER = b"Tacenta Group Roster v1"                        # 23 bytes  [DOM-R]
DOM_CONTEXT = b"Tacenta Group Application v1"                  # 28 bytes  [DOM-C]
DOM_BOOTSTRAP = b"Tacenta Group Invitation Bootstrap v1"       # 37 bytes  [DOM-B]
DOM_ACCEPTANCE = b"Tacenta Group Invitation Acceptance v1"     # 38 bytes  [DOM-A]
DOM_REVOCATION = b"Tacenta Group Invitation Revocation v1"     # 38 bytes  [DOM-V]
DOM_PAYLOAD = b"Tacenta Group Payload v1"                      # 24 bytes  [DOM-P]
DOM_INTENT = b"Tacenta Group Logical Send v1"                  # 29 bytes  [DOM-I]

# The constants of section 2 under the keys section 14 gives them in the vector
# file (`limits`), and the domain strings by format name (`domains`).
LIMITS = {
    "group_id_len": GROUP_ID_LEN,
    "invitation_id_len": INVITATION_ID_LEN,
    "digest_len": DIGEST_LEN,
    "policy_version": POLICY_VERSION,
    "max_members": MAX_MEMBERS,
    "max_identity_len": MAX_IDENTITY,
    "max_device_len": MAX_DEVICE,
    "max_payload_len": MAX_PAYLOAD,
    "max_roster_len": MAX_ROSTER,
    "max_context_len": MAX_CONTEXT,
    "max_group_payload_len": MAX_GROUP_PAYLOAD,
    "reserved_revision": str(RESERVED_REVISION),   # section 14: a decimal string
}
DOMAINS = {
    "roster": DOM_ROSTER.decode("ascii"),
    "context": DOM_CONTEXT.decode("ascii"),
    "bootstrap": DOM_BOOTSTRAP.decode("ascii"),
    "acceptance": DOM_ACCEPTANCE.decode("ascii"),
    "revocation": DOM_REVOCATION.decode("ascii"),
    "payload": DOM_PAYLOAD.decode("ascii"),
    "intent": DOM_INTENT.decode("ascii"),
}

# Section 10 tag table.  Tags 0 and 6..255 are unassigned.
_PAYLOAD_VARIANT = {
    1: "context",       # [PT1]
    2: "roster",        # [PT2]
    3: "bootstrap",     # [PT3]
    4: "acceptance",    # [PT4]
    5: "revocation",    # [PT5]
}

# Section 13 commitment labels.
_ROSTER_LABEL = b"Tacenta:group:roster-commitment:v1"
_PAYLOAD_LABEL = b"Tacenta:group:payload-commitment:v1"


# ---------------------------------------------------------------------------
# Section 1: notation
# ---------------------------------------------------------------------------

def _put_u16(n):
    return n.to_bytes(2, "big")   # section 1: u16, big-endian  [W16]


def _put_u32(n):
    return n.to_bytes(4, "big")   # section 1: u32, big-endian  [W32]


def _put_u64(n):
    return n.to_bytes(8, "big")   # section 1: u64, big-endian  [W64]


def _lp32(x):
    return _put_u32(len(x)) + x   # section 1: lp32(x) = u32(len(x)) || x  [WL32]


def _lp16(x):
    # Section 1: lp16(x) = u16(len(x)) || x, "defined only for len(x) < 65536".
    # Its one user is the bootstrap target, which section 7 "Encoding" has
    # already limited to 256 and 64 bytes, so the prefix cannot overflow.
    return _put_u16(len(x)) + x


def _member_long(m):
    # Section 1: long form = lp32(identity) || lp32(device).
    return _lp32(m[0]) + _lp32(m[1])  # [WML]


def _member_key(m):
    # Section 1 "Member order": the pair (identity, device); never the
    # concatenation identity || device (decision 0136).
    return m  # [MKEY]  (tuple of two byte strings compares lexicographically, unsigned)


def _member_lt(a, b):
    return _member_key(a) < _member_key(b)  # [MLT]  "strictly less in member order"


def _size_check(identity, device):
    # Section 2 "Member size check": identity first, then device.
    if len(identity) > MAX_IDENTITY:  # [SZ1]
        raise Refusal("identity_too_large")
    if len(device) > MAX_DEVICE:  # [SZ2]
        raise Refusal("device_too_large")


class _Reader(object):
    """Section 1 "Reading": a decoder reads its input from the front."""

    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos

    def read(self, n):
        # "if fewer than n remain, decoding stops with the refusal malformed"
        if self.remaining() < n:  # [RD-SHORT]
            raise Refusal("malformed")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_u16(self):
        return int.from_bytes(self.read(2), "big")  # [R16]

    def read_u32(self):
        return int.from_bytes(self.read(4), "big")  # [R32]

    def read_u64(self):
        return int.from_bytes(self.read(8), "big")  # [R64]

    def read_lp32(self):
        n = self.read_u32()  # [RL32]
        return self.read(n)

    def read_lp16(self):
        n = self.read_u16()  # [RL16]
        return self.read(n)

    def read_member(self, check=True):
        # "two consecutive read_lp32() calls (long form) followed by the size
        # check of section 2"
        identity = self.read_lp32()
        device = self.read_lp32()
        if check:  # [RM-CHECK]
            _size_check(identity, device)
        return (identity, device)

    def read_member16(self):
        # "two read_lp16() calls (short form) and performs no size check"
        identity = self.read_lp16()
        device = self.read_lp16()
        return (identity, device)


# ---------------------------------------------------------------------------
# JSON-shape helpers (section 14)
# ---------------------------------------------------------------------------

# Section 14: "byte strings are lowercase hexadecimal of even length"; "A u64 is a
# decimal string (no sign, no leading zero except "0")".  Anything else is not a
# value of the page's types, so an encoder given it raises EncoderInputError
# (section 3, "Encoders": that case is outside the page).
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*\Z")
_DEC_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _hex(b):
    return bytes(b).hex()


def _from_hex(s):
    if not isinstance(s, str) or not _HEX_RE.match(s):  # [IN-HEX]
        raise EncoderInputError("not lowercase even-length hexadecimal: %r" % (s,))
    return bytes.fromhex(s)


def _to_u64(v):
    if not isinstance(v, str) or not _DEC_RE.match(v):  # [IN-U64a]
        raise EncoderInputError("not a decimal u64 string: %r" % (v,))
    n = int(v)
    if n >= 2 ** 64:  # [IN-U64b]
        raise EncoderInputError("u64 out of range: %r" % (v,))
    return n


def _to_uint(v, bits):
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v >= 2 ** bits:  # [IN-UINT]
        raise EncoderInputError("integer out of range for u%d: %r" % (bits, v))
    return v


def _member_to_json(m):
    return {"identity": _hex(m[0]), "device": _hex(m[1])}


def _member_from_json(d):
    return (_from_hex(d["identity"]), _from_hex(d["device"]))


def _fixed(b, n):
    # A fixed-width field of the wrong length is not a value of the page's types
    # (section 3, "Encoders"); outside the page.
    if len(b) != n:  # [FIXED]
        raise EncoderInputError("fixed field of %d bytes, expected %d" % (len(b), n))
    return b


# ---------------------------------------------------------------------------
# Section 5: roster preimage
# ---------------------------------------------------------------------------

def _roster_len(v):
    # Section 5 "Total length".
    n = 104 + len(v["authority"][0]) + len(v["authority"][1])
    for m in v["members"]:
        n += 8 + len(m[0]) + len(m[1])
    return n


def _validate_roster(v):
    """V-roster, section 5 step 12, in order."""
    members = v["members"]
    authority = v["authority"]
    # 12.1
    if v["revision"] == RESERVED_REVISION:  # [RV1]
        raise Refusal("reserved_revision")
    # 12.2
    if v["policy_version"] != POLICY_VERSION:  # [RV2]
        raise Refusal("unsupported_policy")
    # 12.3: revision 0 and any of three conditions -> invalid_genesis
    if v["revision"] == 0:  # [RV3]
        if v["predecessor_digest"] != bytes(DIGEST_LEN):  # [RV3a]
            raise Refusal("invalid_genesis")
        if v["closed"]:  # [RV3b]
            raise Refusal("invalid_genesis")
        if members != [authority]:  # [RV3c]
            raise Refusal("invalid_genesis")
    # 12.4 (cannot fail when decoding: step 9)
    if len(members) > MAX_MEMBERS:  # [RV4]
        raise Refusal("too_many_members")
    # 12.5 (cannot fail when decoding: step 6)
    _size_check(authority[0], authority[1])  # [RV5]
    # 12.6: for each member in order: size check; order; distinct identity
    for i, m in enumerate(members):  # [RV6]
        _size_check(m[0], m[1])  # [RV6a]
        if i > 0 and not _member_lt(members[i - 1], m):  # [RV6b]
            raise Refusal("non_canonical")
        if any(m[0] == e[0] for e in members[:i]):  # [RV6c]
            raise Refusal("non_canonical")
    # 12.7 (cannot fail when decoding: step 1)
    if _roster_len(v) > MAX_ROSTER:  # [RV7]
        raise Refusal("roster_too_large")


def _decode_roster(data):
    """decode_roster(input), section 5."""
    # 1
    if len(data) > MAX_ROSTER:  # [RD1]
        raise Refusal("roster_too_large")
    r = _Reader(data)
    # 2
    if r.read(len(DOM_ROSTER)) != DOM_ROSTER:  # [RD2]
        raise Refusal("malformed")
    # 3
    group_id = r.read_lp32()
    if len(group_id) != GROUP_ID_LEN:  # [RD3]
        raise Refusal("malformed")
    # 4
    revision = r.read_u64()  # [RD4]
    # 5
    predecessor = r.read_lp32()
    if len(predecessor) != DIGEST_LEN:  # [RD5]
        raise Refusal("malformed")
    # 6
    authority = r.read_member()  # [RD6]
    # 7
    policy = r.read_u32()  # [RD7]
    # 8
    closed_byte = r.read(1)[0]
    if closed_byte not in (0, 1):  # [RD8]
        raise Refusal("malformed")
    # 9: a count above 8 is refused before any member is read
    count = r.read_u32()  # [RD9r]
    if count > MAX_MEMBERS:  # [RD9]
        raise Refusal("too_many_members")
    # 10
    members = [r.read_member() for _ in range(count)]  # [RD10]
    # 11
    if r.remaining() != 0:  # [RD11]
        raise Refusal("malformed")
    v = {
        "group_id": group_id,
        "revision": revision,
        "predecessor_digest": predecessor,
        "authority": authority,
        "policy_version": policy,
        "closed": closed_byte == 1,
        "members": members,
    }
    # 12
    _validate_roster(v)  # [RD12]
    return v


def _roster_types(v):
    # Section 3 "Encoders": the group ID and the digest are of their fixed length.
    _fixed(v["group_id"], GROUP_ID_LEN)  # [RE-GID]
    _fixed(v["predecessor_digest"], DIGEST_LEN)  # [RE-DIG]


def _write_roster(v):
    """The layout of section 5 (no checks)."""
    return (
        DOM_ROSTER
        + _lp32(v["group_id"])
        + _put_u64(v["revision"])
        + _lp32(v["predecessor_digest"])
        + _member_long(v["authority"])
        + _put_u32(v["policy_version"])
        + bytes([1 if v["closed"] else 0])
        + _put_u32(len(v["members"]))
        + b"".join(_member_long(m) for m in v["members"])
    )


def _encode_roster(v):
    """Section 5 "Encoding": V-roster on the value, then the layout, "with the same reasons"."""
    _roster_types(v)
    _validate_roster(v)  # [RE-V]
    return _write_roster(v)


def _roster_to_json(v):
    return {
        "group_id": _hex(v["group_id"]),
        "revision": str(v["revision"]),
        "predecessor_digest": _hex(v["predecessor_digest"]),
        "authority": _member_to_json(v["authority"]),
        "policy_version": v["policy_version"],
        "closed": bool(v["closed"]),
        "members": [_member_to_json(m) for m in v["members"]],
    }


def _roster_from_json(f):
    closed = f["closed"]
    if not isinstance(closed, bool):  # [IN-CLOSED]
        raise EncoderInputError("closed must be a boolean: %r" % (closed,))
    return {
        "group_id": _from_hex(f["group_id"]),
        "revision": _to_u64(f["revision"]),
        "predecessor_digest": _from_hex(f["predecessor_digest"]),
        "authority": _member_from_json(f["authority"]),
        "policy_version": _to_uint(f["policy_version"], 32),
        "closed": closed,
        "members": [_member_from_json(m) for m in f["members"]],
    }


# ---------------------------------------------------------------------------
# Section 6: application context
# ---------------------------------------------------------------------------

def _context_len(v):
    # Section 6 "Total length".
    return (120 + len(v["payload"])
            + len(v["sender"][0]) + len(v["sender"][1])
            + len(v["recipient"][0]) + len(v["recipient"][1]))


def _validate_context(v):
    """V-context, section 6 step 11, in order."""
    if v["revision"] == RESERVED_REVISION:  # [CV1]
        raise Refusal("reserved_revision")
    if len(v["payload"]) > MAX_PAYLOAD:  # [CV2]
        raise Refusal("payload_too_large")
    _size_check(v["sender"][0], v["sender"][1])  # [CV3]  (cannot fail when decoding)
    _size_check(v["recipient"][0], v["recipient"][1])  # [CV4]  (cannot fail when decoding)
    if _context_len(v) > MAX_CONTEXT:  # [CV5]  (cannot fail)
        raise Refusal("context_too_large")


def _decode_context(data):
    """decode_context(input), section 6."""
    # 1
    if len(data) > MAX_CONTEXT:  # [CD1]
        raise Refusal("context_too_large")
    r = _Reader(data)
    # 2
    if r.read(len(DOM_CONTEXT)) != DOM_CONTEXT:  # [CD2]
        raise Refusal("malformed")
    # 3
    group_id = r.read_lp32()
    if len(group_id) != GROUP_ID_LEN:  # [CD3]
        raise Refusal("malformed")
    # 4
    revision = r.read_u64()  # [CD4]
    # 5
    digest = r.read_lp32()
    if len(digest) != DIGEST_LEN:  # [CD5]
        raise Refusal("malformed")
    # 6, 7
    sender = r.read_member()  # [CD6]
    recipient = r.read_member()  # [CD7]
    # 8
    sequence = r.read_u64()  # [CD8]
    # 9
    payload = r.read_lp32()  # [CD9]
    # 10
    if r.remaining() != 0:  # [CD10]
        raise Refusal("malformed")
    v = {
        "group_id": group_id,
        "revision": revision,
        "roster_digest": digest,
        "sender": sender,
        "recipient": recipient,
        "logical_sequence": sequence,
        "payload": payload,
    }
    # 11
    _validate_context(v)  # [CD11]
    return v


def _encode_context(v):
    """Section 6 "Encoding": V-context on the value, then the layout."""
    _fixed(v["group_id"], GROUP_ID_LEN)  # [CE-GID]
    _fixed(v["roster_digest"], DIGEST_LEN)  # [CE-DIG]
    _validate_context(v)  # [CE-V]
    return (
        DOM_CONTEXT
        + _lp32(v["group_id"])
        + _put_u64(v["revision"])
        + _lp32(v["roster_digest"])
        + _member_long(v["sender"])
        + _member_long(v["recipient"])
        + _put_u64(v["logical_sequence"])
        + _lp32(v["payload"])
    )


def _context_to_json(v):
    return {
        "group_id": _hex(v["group_id"]),
        "revision": str(v["revision"]),
        "roster_digest": _hex(v["roster_digest"]),
        "sender": _member_to_json(v["sender"]),
        "recipient": _member_to_json(v["recipient"]),
        "logical_sequence": str(v["logical_sequence"]),
        "payload": _hex(v["payload"]),
    }


def _context_from_json(f):
    return {
        "group_id": _from_hex(f["group_id"]),
        "revision": _to_u64(f["revision"]),
        "roster_digest": _from_hex(f["roster_digest"]),
        "sender": _member_from_json(f["sender"]),
        "recipient": _member_from_json(f["recipient"]),
        "logical_sequence": _to_u64(f["logical_sequence"]),
        "payload": _from_hex(f["payload"]),
    }


# ---------------------------------------------------------------------------
# Section 7: invitation bootstrap
# ---------------------------------------------------------------------------

def _decode_bootstrap(data):
    """decode_bootstrap(input), section 7.  No input bound of its own (OP-5)."""
    r = _Reader(data)
    # 1
    if r.read(len(DOM_BOOTSTRAP)) != DOM_BOOTSTRAP:  # [BD1]
        raise Refusal("malformed")
    # 2
    invitation_id = r.read(INVITATION_ID_LEN)  # [BD2a]
    group_id = r.read(GROUP_ID_LEN)  # [BD2b]
    # 3: short form, neither size-checked yet
    target = r.read_member16()  # [BD3]
    # 4
    source_revision = r.read_u64()  # [BD4]
    # 5
    digest = r.read(DIGEST_LEN)  # [BD5]
    # 6
    policy = r.read_u32()  # [BD6]
    # 7
    expires_at = r.read_u64()  # [BD7]
    # 8: the roster bytes MUST decode as a roster; its refusal is ours
    roster_bytes = r.read_lp32()  # [BD8r]
    roster = _decode_roster(roster_bytes)  # [BD8]
    # 9
    if r.remaining() != 0:  # [BD9]
        raise Refusal("malformed")
    # 10: validate the invitation, in order
    if source_revision == RESERVED_REVISION:  # [BV1]
        raise Refusal("reserved_revision")
    if policy != POLICY_VERSION:  # [BV2]
        raise Refusal("unsupported_policy")
    if len(target[0]) > MAX_IDENTITY:  # [BV3]
        raise Refusal("identity_too_large")
    if len(target[1]) > MAX_DEVICE:  # [BV4]
        raise Refusal("device_too_large")
    # 11: validate the bootstrap, in order
    if group_id != roster["group_id"]:  # [BC1]
        raise Refusal("conflict")
    if source_revision != roster["revision"]:  # [BC2]
        raise Refusal("conflict")
    if policy != roster["policy_version"]:  # [BC3]  (cannot fail when decoding)
        raise Refusal("conflict")
    return {
        "invitation_id": invitation_id,
        "group_id": group_id,
        "target": target,
        "source_revision": source_revision,
        "source_roster_digest": digest,
        "policy_version": policy,
        "expires_at": expires_at,
        "source_roster": roster,
    }


def _encode_bootstrap(b):
    """Section 7 "Encoding": three groups of checks, in this order, with the
    decoder's reasons: (1) V-roster on the source roster, in V-roster's order (not
    that of ``decode_roster``); (2) the checks of step 10 on the invitation's own
    fields; (3) the checks of step 11.  It then writes the layout.
    """
    roster = b["source_roster"]
    _fixed(b["invitation_id"], INVITATION_ID_LEN)  # [BE-IID]
    _fixed(b["group_id"], GROUP_ID_LEN)  # [BE-GID]
    _fixed(b["source_roster_digest"], DIGEST_LEN)  # [BE-DIG]
    _roster_types(roster)
    # (1)
    _validate_roster(roster)  # [BE1]
    # (2)
    if b["source_revision"] == RESERVED_REVISION:  # [BE2a]
        raise Refusal("reserved_revision")
    if b["policy_version"] != POLICY_VERSION:  # [BE2b]
        raise Refusal("unsupported_policy")
    if len(b["target"][0]) > MAX_IDENTITY:  # [BE2c]
        raise Refusal("identity_too_large")
    if len(b["target"][1]) > MAX_DEVICE:  # [BE2d]
        raise Refusal("device_too_large")
    # (3)
    if b["group_id"] != roster["group_id"]:  # [BE3a]
        raise Refusal("conflict")
    if b["source_revision"] != roster["revision"]:  # [BE3b]
        raise Refusal("conflict")
    if b["policy_version"] != roster["policy_version"]:  # [BE3c]  (cannot fail)
        raise Refusal("conflict")
    return (
        DOM_BOOTSTRAP
        + b["invitation_id"]
        + b["group_id"]
        + _lp16(b["target"][0])
        + _lp16(b["target"][1])
        + _put_u64(b["source_revision"])
        + b["source_roster_digest"]
        + _put_u32(b["policy_version"])
        + _put_u64(b["expires_at"])
        + _lp32(_write_roster(roster))
    )


def _bootstrap_to_json(v):
    return {
        "invitation_id": _hex(v["invitation_id"]),
        "group_id": _hex(v["group_id"]),
        "target": _member_to_json(v["target"]),
        "source_revision": str(v["source_revision"]),
        "source_roster_digest": _hex(v["source_roster_digest"]),
        "policy_version": v["policy_version"],
        "expires_at": str(v["expires_at"]),
        "source_roster": _roster_to_json(v["source_roster"]),
    }


def _bootstrap_from_json(f):
    return {
        "invitation_id": _from_hex(f["invitation_id"]),
        "group_id": _from_hex(f["group_id"]),
        "target": _member_from_json(f["target"]),
        "source_revision": _to_u64(f["source_revision"]),
        "source_roster_digest": _from_hex(f["source_roster_digest"]),
        "policy_version": _to_uint(f["policy_version"], 32),
        "expires_at": _to_u64(f["expires_at"]),
        "source_roster": _roster_from_json(f["source_roster"]),
    }


# ---------------------------------------------------------------------------
# Sections 8 and 9: invitation acceptance and revocation
# ---------------------------------------------------------------------------

def _decode_ack(data, domain):
    """decode_acceptance / decode_revocation (same steps, section 9)."""
    r = _Reader(data)
    # 1
    if r.read(len(domain)) != domain:  # [AD1]
        raise Refusal("malformed")
    # 2
    group_id = r.read(GROUP_ID_LEN)  # [AD2a]
    invitation_id = r.read(INVITATION_ID_LEN)  # [AD2b]
    # 3
    source_revision = r.read_u64()  # [AD3a]
    digest = r.read(DIGEST_LEN)  # [AD3b]
    # 4
    if r.remaining() != 0:  # [AD4]
        raise Refusal("malformed")
    # 5
    if source_revision == RESERVED_REVISION:  # [AD5]
        raise Refusal("reserved_revision")
    return {
        "group_id": group_id,
        "invitation_id": invitation_id,
        "source_revision": source_revision,
        "source_roster_digest": digest,
    }


def _encode_ack(v, domain):
    """Section 8 "Encoding": refuses a reserved revision and writes the layout."""
    _fixed(v["group_id"], GROUP_ID_LEN)  # [AE-GID]
    _fixed(v["invitation_id"], INVITATION_ID_LEN)  # [AE-IID]
    _fixed(v["source_roster_digest"], DIGEST_LEN)  # [AE-DIG]
    if v["source_revision"] == RESERVED_REVISION:  # [AE-RES]
        raise Refusal("reserved_revision")
    return (
        domain
        + v["group_id"]
        + v["invitation_id"]
        + _put_u64(v["source_revision"])
        + v["source_roster_digest"]
    )


def _ack_to_json(v):
    return {
        "group_id": _hex(v["group_id"]),
        "invitation_id": _hex(v["invitation_id"]),
        "source_revision": str(v["source_revision"]),
        "source_roster_digest": _hex(v["source_roster_digest"]),
    }


def _ack_from_json(f):
    return {
        "group_id": _from_hex(f["group_id"]),
        "invitation_id": _from_hex(f["invitation_id"]),
        "source_revision": _to_u64(f["source_revision"]),
        "source_roster_digest": _from_hex(f["source_roster_digest"]),
    }


# ---------------------------------------------------------------------------
# Section 11: logical-send intent
# ---------------------------------------------------------------------------

def _decode_intent(data):
    """decode_intent(input), section 11.  No input bound of its own."""
    r = _Reader(data)
    # 1
    if r.read(len(DOM_INTENT)) != DOM_INTENT:  # [ID1]
        raise Refusal("malformed")
    # 2
    group_id = r.read_lp32()
    if len(group_id) != GROUP_ID_LEN:  # [ID2]
        raise Refusal("malformed")
    # 3
    revision = r.read_u64()  # [ID3]
    # 4
    sender = r.read_member()  # [ID4]
    # 5
    sequence = r.read_u64()  # [ID5]
    # 6
    digest = r.read_lp32()
    if len(digest) != DIGEST_LEN:  # [ID6]
        raise Refusal("malformed")
    # 7
    payload = r.read_lp32()
    if len(payload) > MAX_PAYLOAD:  # [ID7]
        raise Refusal("payload_too_large")
    # 8: both before any recipient is read
    count = r.read_u32()  # [ID8r]
    if count == 0:  # [ID8a]
        raise Refusal("empty_recipients")
    if count > MAX_MEMBERS:  # [ID8b]
        raise Refusal("too_many_members")
    # 9
    recipients = [r.read_member() for _ in range(count)]  # [ID9]
    # 10
    if r.remaining() != 0:  # [ID10]
        raise Refusal("malformed")
    # 11
    for i, m in enumerate(recipients):  # [ID11]
        if i > 0 and not _member_lt(recipients[i - 1], m):  # [ID11a]
            raise Refusal("non_canonical")
        if any(m[0] == e[0] for e in recipients[:i]):  # [ID11b]
            raise Refusal("non_canonical")
    # 12
    if revision == RESERVED_REVISION:  # [ID12]
        raise Refusal("reserved_revision")
    return {
        "group_id": group_id,
        "revision": revision,
        "sender": sender,
        "sequence": sequence,
        "roster_digest": digest,
        "payload": payload,
        "recipients": recipients,
    }


def _encode_intent(v):
    """Section 11 "Encoding": the decoder's checks on the value, in the order in
    which the decoder meets them (steps 4, 7, 8, 9, 11, 12), with the decoder's
    reasons, then the layout.
    """
    _fixed(v["group_id"], GROUP_ID_LEN)  # [IE-GID]
    _fixed(v["roster_digest"], DIGEST_LEN)  # [IE-DIG]
    recipients = v["recipients"]
    # 1: the sender's size (step 4)
    _size_check(v["sender"][0], v["sender"][1])  # [IE1]
    # 2: the payload (step 7)
    if len(v["payload"]) > MAX_PAYLOAD:  # [IE2]
        raise Refusal("payload_too_large")
    # 3: the number of recipients (step 8)
    if len(recipients) == 0:  # [IE3a]
        raise Refusal("empty_recipients")
    if len(recipients) > MAX_MEMBERS:  # [IE3b]
        raise Refusal("too_many_members")
    # 4: each recipient's size, in order (step 9)
    for m in recipients:  # [IE4]
        _size_check(m[0], m[1])
    # 5: order and distinct identities, in order (step 11)
    for i, m in enumerate(recipients):  # [IE5]
        if i > 0 and not _member_lt(recipients[i - 1], m):  # [IE5a]
            raise Refusal("non_canonical")
        if any(m[0] == e[0] for e in recipients[:i]):  # [IE5b]
            raise Refusal("non_canonical")
    # 6: the revision (step 12)
    if v["revision"] == RESERVED_REVISION:  # [IE6]
        raise Refusal("reserved_revision")
    return (
        DOM_INTENT
        + _lp32(v["group_id"])
        + _put_u64(v["revision"])
        + _member_long(v["sender"])
        + _put_u64(v["sequence"])
        + _lp32(v["roster_digest"])
        + _lp32(v["payload"])
        + _put_u32(len(recipients))
        + b"".join(_member_long(m) for m in recipients)
    )


def _intent_to_json(v):
    return {
        "group_id": _hex(v["group_id"]),
        "revision": str(v["revision"]),
        "sender": _member_to_json(v["sender"]),
        "sequence": str(v["sequence"]),
        "roster_digest": _hex(v["roster_digest"]),
        "payload": _hex(v["payload"]),
        "recipients": [_member_to_json(m) for m in v["recipients"]],
    }


def _intent_from_json(f):
    return {
        "group_id": _from_hex(f["group_id"]),
        "revision": _to_u64(f["revision"]),
        "sender": _member_from_json(f["sender"]),
        "sequence": _to_u64(f["sequence"]),
        "roster_digest": _from_hex(f["roster_digest"]),
        "payload": _from_hex(f["payload"]),
        "recipients": [_member_from_json(m) for m in f["recipients"]],
    }


# ---------------------------------------------------------------------------
# Format table (everything except the group payload, which dispatches on it)
# ---------------------------------------------------------------------------

def _decode_value(fmt, data):
    """Bytes -> JSON-shaped fields for the six non-payload formats."""
    if fmt == "roster":
        return _roster_to_json(_decode_roster(data))
    if fmt == "context":
        return _context_to_json(_decode_context(data))
    if fmt == "bootstrap":
        return _bootstrap_to_json(_decode_bootstrap(data))
    if fmt == "acceptance":
        return _ack_to_json(_decode_ack(data, DOM_ACCEPTANCE))
    if fmt == "revocation":
        return _ack_to_json(_decode_ack(data, DOM_REVOCATION))
    if fmt == "intent":
        return _intent_to_json(_decode_intent(data))
    raise ValueError("unknown format: %r" % (fmt,))


def _encode_value(fmt, fields):
    if fmt == "roster":
        return _encode_roster(_roster_from_json(fields))
    if fmt == "context":
        return _encode_context(_context_from_json(fields))
    if fmt == "bootstrap":
        return _encode_bootstrap(_bootstrap_from_json(fields))
    if fmt == "acceptance":
        return _encode_ack(_ack_from_json(fields), DOM_ACCEPTANCE)
    if fmt == "revocation":
        return _encode_ack(_ack_from_json(fields), DOM_REVOCATION)
    if fmt == "intent":
        return _encode_intent(_intent_from_json(fields))
    raise ValueError("unknown format: %r" % (fmt,))


# ---------------------------------------------------------------------------
# Section 10: group payload
# ---------------------------------------------------------------------------

def _unknown_tag(value):
    # Section 10 step 5: "a tag outside 1 to 5 is `malformed`"; also "The tag
    # values 0 and 6 to 255 are unassigned and refused."
    raise Refusal("malformed")  # [PD5a]


def _variant_decoder(fmt):
    return lambda value: _decode_value(fmt, value)


# Section 10 step 5: "the value is decoded by the decoder of the table".
_PAYLOAD_DECODER = dict((tag, _variant_decoder(fmt)) for tag, fmt in _PAYLOAD_VARIANT.items())


def _decode_payload(data):
    """decode_payload(input), section 10."""
    # 1: bound and domain, both `malformed`
    if len(data) > MAX_GROUP_PAYLOAD or not data.startswith(DOM_PAYLOAD):  # [PD1]
        raise Refusal("malformed")
    r = _Reader(data)
    r.read(len(DOM_PAYLOAD))
    # 2
    tag = r.read(1)[0]  # [PD2]
    # 3
    length = r.read_u32()  # [PD3]
    # 4: the remaining bytes number exactly `length`
    if r.remaining() != length:  # [PD4]
        raise Refusal("malformed")
    value = r.read(length)
    # 5: dispatch on the tag; any refusal of the variant's decoder is ours, unchanged
    decoder = _PAYLOAD_DECODER.get(tag, _unknown_tag)  # [PD5]
    return {"tag": tag, "value": decoder(value)}


def _encode_payload(fields):
    """Section 10 "Encoding": domain, tag, u32(len(value)), value; `malformed` if the whole is over 8,192."""
    tag = _to_uint(fields["tag"], 8)
    fmt = _PAYLOAD_VARIANT.get(tag)  # [PE-TAG]
    if fmt is None:
        # Section 3 "Encoders": the tag is from 1 to 5; anything else is outside the page.
        raise EncoderInputError("payload tag %r is not from 1 to 5" % (tag,))
    value = _encode_value(fmt, fields["value"])  # [PE-VAL]  refuses what the variant's encoder refuses
    out = DOM_PAYLOAD + bytes([tag]) + _put_u32(len(value)) + value  # [PE-LAY]
    if len(out) > MAX_GROUP_PAYLOAD:  # [PE-MAX]  (cannot fail for a valid variant)
        raise Refusal("malformed")
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decode(fmt, data):
    """Decode ``data`` as format ``fmt``; return fields or raise Refusal."""
    data = bytes(data)
    if fmt == "payload":
        return _decode_payload(data)
    return _decode_value(fmt, data)


def encode(fmt, fields):
    """Encode ``fields`` as format ``fmt``; return bytes, or raise Refusal (the refusals of each
    "Encoding" paragraph) or EncoderInputError (input that is not a value of the page's types)."""
    if fmt == "payload":
        return _encode_payload(fields)
    return _encode_value(fmt, fields)


def roster_commitment(preimage):
    """Section 13: SHA-256(label || 0xFF || preimage); 32 raw bytes."""
    return hashlib.sha256(_ROSTER_LABEL + b"\xff" + bytes(preimage)).digest()


def payload_commitment(context):
    """Section 13: SHA-256(label || 0xFF || context); 32 raw bytes."""
    return hashlib.sha256(_PAYLOAD_LABEL + b"\xff" + bytes(context)).digest()
