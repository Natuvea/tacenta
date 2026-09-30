#!/usr/bin/env python3
"""Every committed conformance vector file is non-empty, and stays as large as it was.

    python3 tooling/check-vectors.py

The files under `contracts/vectors/` are what the Rust readers replay and what
the Lean model regenerates. A reader that loops over an empty list passes
without having checked anything, and a file cut down to a single easy case
passes every reader that only asks for "not empty". So this holds each file to
a floor: the format it names, the list of cases it must carry, how many, and
what the cases must contain. The floors below are the sizes the files have
today; a deliberate change that shrinks a file lowers its floor in the same
change, where a reader of the diff sees it.

A file fails if it is zero bytes or only whitespace, is not valid JSON, is not
an object, repeats a key (parsers disagree about which copy wins), names a
`format` other than its file name, lacks its case list or has a case list
that is not a list, carries fewer cases than the floor, has a case that is
not an object or lacks a field, has a case in which a field the floor requires
to be non-empty is empty, or has fewer nested items in total than the floor.
A file under `contracts/vectors/` with no entry below fails too, so a new
vector file cannot be added without stating how much it must contain; and an
entry with no file fails, so a floor cannot outlive its file.

What this does not establish: that the cases are right. The Rust readers replay
them, `lake exe vectors` regenerates them in CI, and the floors here only make
sure that neither is looking at an empty or shrunken file. A change that edits
a file and its floor together passes (docs/reproduce.md, "What these gates
cannot defend against").
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(ROOT, "contracts", "vectors")

# file name -> the shape and the floor.
#   list         the top-level key holding the cases
#   min          fewest cases
#   fields       every case is an object with all of these keys
#   each_filled  fields that must be a non-empty list in every case
#   some_filled  fields that must be a non-empty list in at least one case
#                (an empty case is a legitimate vector, so not "in every case")
#   items        {field: fewest items in total, over all cases}
#   kinds        {value: fewest cases} for the `kind` field
FLOORS = {
    "envelope-v1.json": {
        "list": "vectors", "min": 5,
        "fields": ("kind", "payload", "encoded"),
        "kinds": {"dm": 1, "group": 1, "receipt": 1},
    },
    "group-v1.json": {
        "list": "traces", "min": 10,
        "fields": ("name", "authority", "steps"),
        "each_filled": ("steps",),
        "items": {"steps": 104},
    },
    "group-wire-v1.json": {
        "list": "vectors", "min": 377,
        "fields": ("name", "format", "result"),
    },
    "session-v1.json": {
        "list": "traces", "min": 4,
        "fields": ("ops", "final"),
        "some_filled": ("ops",),
        "items": {"ops": 12},
    },
    "stream-v1.json": {
        "list": "streams", "min": 4,
        "fields": ("envelopes", "encoded"),
        "some_filled": ("envelopes",),
    },
    "user-v1.json": {
        "list": "traces", "min": 4,
        "fields": ("ops", "final"),
        "some_filled": ("ops",),
        "items": {"ops": 14},
    },
}


def no_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError("repeats the key %r" % key)
        seen.add(key)
    return dict(pairs)


def check(name, floor, problems):
    path = os.path.join(VECTORS, name)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        problems.append("%s: cannot read: %s" % (name, error))
        return
    if not text.strip():
        problems.append("%s: the file is empty" % name)
        return
    try:
        doc = json.loads(text, object_pairs_hook=no_duplicates)
    except ValueError as error:
        problems.append("%s: not valid JSON: %s" % (name, error))
        return
    if not isinstance(doc, dict):
        problems.append("%s: the top level is not an object" % name)
        return

    expected = name[: -len(".json")]
    if doc.get("format") != expected:
        problems.append("%s: format is %r, expected %r"
                        % (name, doc.get("format"), expected))

    key = floor["list"]
    cases = doc.get(key)
    if not isinstance(cases, list):
        problems.append("%s: `%s` is missing or not a list" % (name, key))
        return
    if len(cases) < floor["min"]:
        problems.append("%s: %d case(s) in `%s`, the floor is %d"
                        % (name, len(cases), key, floor["min"]))

    usable = []
    for index, case in enumerate(cases):
        where = "%s: %s[%d]" % (name, key, index)
        if not isinstance(case, dict):
            problems.append("%s is not an object" % where)
            continue
        missing = [f for f in floor["fields"] if f not in case]
        if missing:
            problems.append("%s lacks %s" % (where, ", ".join(missing)))
            continue
        usable.append(case)
        for field in floor.get("each_filled", ()):
            if not isinstance(case[field], list) or not case[field]:
                problems.append("%s has an empty `%s`" % (where, field))

    for field in floor.get("some_filled", ()):
        if not any(isinstance(c[field], list) and c[field] for c in usable):
            problems.append("%s: no case has a non-empty `%s`" % (name, field))

    for field, least in floor.get("items", {}).items():
        total = sum(len(c[field]) for c in usable if isinstance(c[field], list))
        if total < least:
            problems.append("%s: %d `%s` item(s) in all, the floor is %d"
                            % (name, total, field, least))

    for kind, least in floor.get("kinds", {}).items():
        have = sum(1 for c in usable if c.get("kind") == kind)
        if have < least:
            problems.append("%s: %d case(s) of kind %r, the floor is %d"
                            % (name, have, kind, least))

    if not any(p.startswith(name + ":") for p in problems):
        print("check-vectors: %s: %d %s, meets its floor of %d"
              % (name, len(cases), key, floor["min"]))


def main():
    problems = []
    try:
        present = sorted(n for n in os.listdir(VECTORS) if n.endswith(".json"))
    except OSError as error:
        print("check-vectors: cannot list %s: %s" % (VECTORS, error),
              file=sys.stderr)
        return 1
    for name in present:
        if name not in FLOORS:
            problems.append("%s: no floor in tooling/check-vectors.py; add one "
                            "in the change that adds the file" % name)
    for name, floor in sorted(FLOORS.items()):
        if name not in present:
            problems.append("%s: has a floor but the file is not in "
                            "contracts/vectors/" % name)
        else:
            check(name, floor, problems)
    if problems:
        for problem in problems:
            print("check-vectors: " + problem, file=sys.stderr)
        return 1
    print("check-vectors: %d vector file(s) meet their floors" % len(FLOORS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
