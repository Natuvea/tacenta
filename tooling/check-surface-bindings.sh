#!/usr/bin/env bash
# The surface manifest's Swift or Kotlin column against the bindings UniFFI
# actually generated (decision 0090): every symbol the manifest says
# a head has must be declared in the generated source, spelt as generated,
# and a qualified symbol (`Tenant.signIn`) inside that object's own class
# rather than anywhere in the file. The in-crate test infers the names from
# the Rust exports; this checks the thing that ships.
# Usage: check-surface-bindings.sh swift <file> | kotlin <dir>
set -euo pipefail
cd "$(dirname "$0")/.."
head=${1:?swift or kotlin}
where=${2:?generated source file or directory}
python3 - "$head" "$where" <<'PY'
import json, re, sys
from pathlib import Path

head, where = sys.argv[1], Path(sys.argv[2])
keyword = {"swift": "func", "kotlin": "fun"}[head]
sources = [where] if where.is_file() else sorted(where.rglob("*.swift" if head == "swift" else "*.kt"))
text = "\n".join(p.read_text() for p in sources)

def decl_body(name):
    # The brace-balanced body of `class NAME` or `enum NAME`. UniFFI's Swift
    # is not indented, so nothing about columns can be relied on; Kotlin
    # nests the constructors in a companion object and breaks the line
    # before the class brace, which the balance walks through.
    m = re.search(rf"^(?:open |public |final |sealed |abstract |indirect )*(?:class|enum) {name}\b[^{{]*\{{", text, re.M)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(text) and depth > 0:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i]

def declared(body, name):
    # UniFFI's Kotlin wraps names in backticks; Swift does not.
    return re.search(rf"\b{keyword}\s+`?{re.escape(name)}`?[\s(<]", body) is not None

def error_declared(cls, name):
    # Swift: `case Name(reason: String)` inside `public enum ClientError`;
    # Kotlin: `class Name(...) : ClientException(...)` inside the sealed class.
    body = decl_body(cls)
    if body is None:
        return False
    word = "case" if head == "swift" else "class"
    return re.search(rf"\b{word}\s+{re.escape(name)}\s*\(", body) is not None

manifest = json.load(open("sdk/surface.json"))
missing, checked = [], 0
for kind in manifest.get("errors", {}).get("kinds", []):
    symbol = kind.get(head)
    if not symbol:
        continue
    checked += 1
    cls, name = symbol.split(".", 1)
    if not error_declared(cls, name):
        missing.append(symbol)
for obj in manifest["objects"]:
    for call in obj["calls"]:
        symbol = call.get(head)
        if not symbol:
            continue
        checked += 1
        if "." in symbol:
            cls, name = symbol.split(".", 1)
            body = decl_body(cls)
            ok = body is not None and declared(body, name)
        else:
            ok = declared(text, symbol)
        if not ok:
            missing.append(symbol)
if checked == 0:
    print(f"check-surface-bindings: the manifest names no {head} symbols", file=sys.stderr)
    sys.exit(1)
for s in missing:
    print(f"check-surface-bindings: {head}: {s} is in sdk/surface.json but not declared where it should be in {where}", file=sys.stderr)
if missing:
    sys.exit(1)
print(f"check-surface-bindings: every {head} symbol in the manifest is declared in the generated bindings ({checked} checked)")
PY
