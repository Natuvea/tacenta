#!/usr/bin/env python3
"""Render sdk/surface.json as the parity grid, sdk/SURFACE.md.

Generated, never edited: tooling/check-surface.sh regenerates and diffs, so
the grid on disk is always the manifest's (decision 0090). Python
rather than Node so the gate runs wherever the other gates do.
"""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
manifest = json.loads((root / "sdk" / "surface.json").read_text())
heads = list(manifest["heads"])

lines = [
    "# The SDK surface",
    "",
    "Generated from `sdk/surface.json` by `tooling/surface-grid.py`; do not edit.",
    "A cell is the symbol that head exposes for the call, or a dash where the head",
    "does not have it yet, with the gap named beneath the table. Each head's test",
    "suite checks itself against the manifest, so this grid cannot drift from the",
    "code without a test failing (decision 0090).",
    "",
]
for obj in manifest["objects"]:
    lines += [f"## {obj['name']}", "", obj["about"], "",
              "| Call | " + " | ".join(heads) + " |",
              "|---|" + "|".join("---" for _ in heads) + "|"]
    for call in obj["calls"]:
        cells = [f"`{call[h]}`" if call.get(h) else "-" for h in heads]
        lines.append(f"| {call['name']} | " + " | ".join(cells) + " |")
    gaps = [c for c in obj["calls"] if c.get("gap")]
    if gaps:
        lines.append("")
        lines += [f"- **{c['name']}**: {c['gap']}" for c in gaps]
    lines.append("")
errors = manifest.get("errors")
if errors:
    lines += ["## Errors", "", errors["about"], "",
              "| Kind | " + " | ".join(heads) + " |",
              "|---|" + "|".join("---" for _ in heads) + "|"]
    for kind in errors["kinds"]:
        cells = [f"`{kind[h]}`" if kind.get(h) else "-" for h in heads]
        lines.append(f"| {kind['name']} | " + " | ".join(cells) + " |")
    lines.append("")
    lines += [f"- **{k['name']}**: {k['about']}" for k in errors["kinds"]]
    lines.append("")
out = "\n".join(lines)
target = root / "sdk" / "SURFACE.md"
if "--check" in sys.argv:
    if target.read_text() != out:
        print("check-surface: sdk/SURFACE.md is not what sdk/surface.json renders to; "
              "run python3 tooling/surface-grid.py", file=sys.stderr)
        sys.exit(1)
    print("check-surface: sdk/SURFACE.md matches sdk/surface.json")
else:
    target.write_text(out)
    print(f"wrote {target}")
