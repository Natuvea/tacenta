#!/usr/bin/env bash
# Fail if a strong-copyleft crate reaches the product build graph.
#
# The invariant: the product depends on nothing under the AGPL or GPL, and it
# is enforced by asking the build what it resolves rather than by convention.
#
# `--all-features` is deliberate: a plain `cargo tree` omits optional
# dependencies, so the question answered here is not "does the default build
# pull one" but "can this workspace pull one at all".
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "no-agpl: resolving the product graph"

# Licence metadata, not crate names: renaming a crate should not evade this.
found="$(cargo metadata --format-version 1 --all-features 2>/dev/null | python3 -c '
import json, sys
m = json.load(sys.stdin)
strong, missing = [], []
for p in m["packages"]:
    lic = (p.get("license") or "").upper()
    # AGPL and GPL are the strong-copyleft families.
    # An "OR" list means we may choose a permissive branch, so it is not a hit.
    if ("AGPL" in lic or "GPL" in lic) and " OR " not in lic:
        strong.append("%s %s -> %s" % (p["name"], p["version"], p["license"]))
    # Missing licence metadata on a THIRD-PARTY crate is a gap, not a pass: an
    # unlabelled dependency could be anything. Exempt what is ours: workspace-local
    # path crates (source is null) and our own crates pulled from a Natuvea git
    # repo (Apache-2.0 via that repo LICENSE; they set no per-crate license field).
    src = p.get("source") or ""
    ours = (src == "") or ("github.com/Natuvea/" in src)
    if not ours and not (p.get("license") or p.get("license_file")):
        missing.append("%s %s (no license or license-file field)" % (p["name"], p["version"]))
if strong:
    print("STRONG-COPYLEFT:")
    print("\n".join(sorted(set(strong))))
if missing:
    print("NO-LICENCE-METADATA:")
    print("\n".join(sorted(set(missing))))
')"

if [ -n "$found" ]; then
  echo "" >&2
  echo "ERROR: the product build graph failed the licence check." >&2
  echo "" >&2
  echo "$found" >&2
  echo "" >&2
  echo "STRONG-COPYLEFT: the product must not depend on AGPL or GPL code." >&2
  echo "Remove the dependency or the feature that pulls it before proceeding." >&2
  echo "NO-LICENCE-METADATA: an external crate with no declared licence must be" >&2
  echo "resolved (identify its licence, or pin/replace it) -- not silently" >&2
  echo "accepted." >&2
  echo "" >&2
  exit 1
fi

# Scope note: this checks the Cargo graph only. Before publishing packages, also
# inspect the npm, Gradle/Maven and Swift-tooling graphs and the final binary
# SBOMs (the .aar / xcframework contents), which this check does not cover.
echo "no-agpl: no AGPL/GPL crate, and every external crate declares a licence (Cargo graph only)"
