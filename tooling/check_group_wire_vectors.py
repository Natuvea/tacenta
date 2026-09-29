#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Replay ``vectors/group-wire-v1.json`` against ``group_wire_reference``.

Usage: check_group_wire_vectors.py [VECTOR_FILE]

Every vector of every ``result`` kind (section 14 of the specification) is
replayed:

  valid            decode ``bytes`` to ``fields``, and encode ``fields`` to ``bytes``
  refuse           refuse ``bytes`` with ``reason``
  refuse_prefixes  refuse every proper prefix of ``bytes`` (lengths 0..len-1)
  encode_refuse    refuse to encode ``fields`` with ``reason``

``pad_to`` appends 00 bytes up to that total length; ``bytes`` may be empty.
Every ``commitments`` entry is checked with hashlib.  Section 14 also fixes the
file header and a few rules for the file itself, and these are checked too:
``format`` is ``group-wire-v1``; ``limits`` holds exactly the constants of
section 2 under the keys section 14 lists; ``domains`` maps the seven format names
to their domain strings; a vector name is unique and reads ``format/case``, and an
``encode_refuse`` name (and only that kind) reads ``format/encode-...``; ``pad_to``
occurs only on ``refuse`` and is never below the length of ``bytes``.  A header or
file-rule failure prints as ``FAIL file/...`` and counts as one failure.

One line is printed per failing vector, then
``group-wire: N vectors, M failed, K commitments``.  The exit status is non-zero
when anything failed.
"""

import hashlib
import json
import os
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import group_wire_reference as ref  # noqa: E402

DEFAULT_VECTORS = os.path.join(HERE, "vectors", "group-wire-v1.json")


def strict_equal(a, b):
    """JSON equality that does not confuse True with 1 or "1" with 1."""
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def vector_input(v):
    data = bytes.fromhex(v["bytes"])
    pad_to = v.get("pad_to")
    if pad_to is not None and len(data) < pad_to:
        data += b"\x00" * (pad_to - len(data))
    return data


def expect_refusal(call, reason):
    """Return None when ``call()`` raises Refusal(reason), else a message."""
    try:
        got = call()
    except ref.Refusal as exc:
        if exc.reason == reason:
            return None
        return "expected refusal %r, got refusal %r" % (reason, exc.reason)
    except Exception as exc:  # a crash is a failure, not a refusal
        return "expected refusal %r, got %s: %s" % (reason, type(exc).__name__, exc)
    return "expected refusal %r, got a value: %r" % (reason, _short(got))


def _short(x):
    s = repr(x)
    return s if len(s) <= 100 else s[:97] + "..."


def check_vector(v):
    """Return None when the vector passes, else a one-line failure message."""
    fmt = v["format"]
    kind = v["result"]
    if kind == "valid":
        data = vector_input(v)
        try:
            got = ref.decode(fmt, data)
        except ref.Refusal as exc:
            return "decode refused %r, expected a value" % exc.reason
        except Exception as exc:
            return "decode crashed: %s: %s" % (type(exc).__name__, exc)
        if not strict_equal(got, v["fields"]):
            return "decode gave different fields"
        try:
            enc = ref.encode(fmt, v["fields"])
        except ref.Refusal as exc:
            return "encode refused %r, expected bytes" % exc.reason
        except Exception as exc:
            return "encode crashed: %s: %s" % (type(exc).__name__, exc)
        if enc != data:
            return "encode gave different bytes"
        return None
    if kind == "refuse":
        data = vector_input(v)
        return expect_refusal(lambda: ref.decode(fmt, data), v["reason"])
    if kind == "refuse_prefixes":
        data = vector_input(v)
        for n in range(len(data)):
            prefix = data[:n]
            msg = expect_refusal(lambda: ref.decode(fmt, prefix), v["reason"])
            if msg is not None:
                return "prefix of length %d: %s" % (n, msg)
        return None
    if kind == "encode_refuse":
        return expect_refusal(lambda: ref.encode(fmt, v["fields"]), v["reason"])
    return "unknown result kind %r" % (kind,)


def check_commitment(i, c):
    try:
        pre = bytes.fromhex(c["preimage"])
        if c["kind"] == "roster":
            label = b"Tacenta:group:roster-commitment:v1"
            via = ref.roster_commitment
        elif c["kind"] == "payload":
            label = b"Tacenta:group:payload-commitment:v1"
            via = ref.payload_commitment
        else:
            return "unknown commitment kind %r" % (c["kind"],)
        want = hashlib.sha256(label + b"\xff" + pre).hexdigest()  # section 13, by hashlib
        if want != c["digest"]:
            return "digest in file differs from SHA-256 over the preimage"
        if via(pre).hex() != c["digest"]:
            return "reference commitment function differs from the file"
    except Exception as exc:
        return "%s: %s" % (type(exc).__name__, exc)
    return None


RESULT_MEMBERS = {
    "valid": {"bytes", "fields"},
    "refuse": {"bytes", "reason", "pad_to"},
    "refuse_prefixes": {"bytes", "reason"},
    "encode_refuse": {"fields", "reason"},
}
REQUIRED = {"valid": {"bytes", "fields"}, "refuse": {"bytes", "reason"},
            "refuse_prefixes": {"bytes", "reason"}, "encode_refuse": {"fields", "reason"}}
REASONS = {"malformed", "non_canonical", "unsupported_policy", "reserved_revision", "invalid_genesis",
           "too_many_members", "payload_too_large", "identity_too_large", "device_too_large",
           "roster_too_large", "context_too_large", "conflict", "empty_recipients"}


def check_header(doc):
    """Section 14 'File layout': format, limits, domains.  Yields failure messages."""
    if doc.get("format") != "group-wire-v1":
        yield ("file/format", "format is %r, expected 'group-wire-v1'" % (doc.get("format"),))
    limits = doc.get("limits")
    if not isinstance(limits, dict):
        yield ("file/limits", "limits is not an object")
    else:
        for key in sorted(set(limits) | set(ref.LIMITS)):
            if key not in limits:
                yield ("file/limits/" + key, "key missing from the file")
            elif key not in ref.LIMITS:
                yield ("file/limits/" + key, "key not listed in section 14")
            elif not strict_equal(limits[key], ref.LIMITS[key]):
                yield ("file/limits/" + key, "file has %r, reference constant is %r" % (limits[key], ref.LIMITS[key]))
    domains = doc.get("domains")
    if not isinstance(domains, dict):
        yield ("file/domains", "domains is not an object")
    else:
        for key in sorted(set(domains) | set(ref.DOMAINS)):
            if key not in domains:
                yield ("file/domains/" + key, "format missing from the file")
            elif key not in ref.DOMAINS:
                yield ("file/domains/" + key, "not one of the seven formats")
            elif not strict_equal(domains[key], ref.DOMAINS[key]):
                yield ("file/domains/" + key, "file has %r, reference constant is %r" % (domains[key], ref.DOMAINS[key]))


def check_file_rules(vectors):
    """Section 14 'A vector' and 'pad_to': rules about the file itself."""
    seen = set()
    for v in vectors:
        name = v.get("name", "?")
        fmt, kind = v.get("format"), v.get("result")
        if name in seen:
            yield ("file/" + name, "duplicate vector name")
        seen.add(name)
        if fmt not in ref.DOMAINS:
            yield ("file/" + name, "unknown format %r" % (fmt,))
            continue
        if not name.startswith(fmt + "/"):
            yield ("file/" + name, "name does not start with 'format/'")
        if (kind == "encode_refuse") != name.startswith(fmt + "/encode-"):
            yield ("file/" + name, "'format/encode-' names exactly the encode_refuse vectors")
        if kind not in RESULT_MEMBERS:
            yield ("file/" + name, "unknown result %r" % (kind,))
            continue
        keys = set(v) - {"name", "format", "result"}
        if not REQUIRED[kind] <= keys or not keys <= RESULT_MEMBERS[kind]:
            yield ("file/" + name, "members %s do not fit result %r" % (sorted(keys), kind))
        if "reason" in v and v["reason"] not in REASONS:
            yield ("file/" + name, "reason %r is not a label of section 3" % (v["reason"],))
        if "bytes" in v:
            b = v["bytes"]
            if not isinstance(b, str) or len(b) % 2 or b != b.lower() or any(c not in "0123456789abcdef" for c in b):
                yield ("file/" + name, "bytes is not lowercase hexadecimal of even length")
            elif "pad_to" in v and (isinstance(v["pad_to"], bool) or not isinstance(v["pad_to"], int)
                                    or v["pad_to"] < len(b) // 2):
                yield ("file/" + name, "pad_to is below the length of bytes")


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT_VECTORS
    with open(path, "r") as fh:
        doc = json.load(fh)
    failed = 0
    vectors = doc["vectors"]
    for name, msg in list(check_header(doc)) + list(check_file_rules(vectors)):
        failed += 1
        print("FAIL %s: %s" % (name, msg))
    for v in vectors:
        msg = check_vector(v)
        if msg is not None:
            failed += 1
            print("FAIL %s: %s" % (v.get("name", "?"), msg))
    commitments = doc.get("commitments", [])
    for i, c in enumerate(commitments):
        msg = check_commitment(i, c)
        if msg is not None:
            failed += 1
            print("FAIL commitment[%d] (%s): %s" % (i, c.get("kind"), msg))
    print("group-wire: %d vectors, %d failed, %d commitments"
          % (len(vectors), failed, len(commitments)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
