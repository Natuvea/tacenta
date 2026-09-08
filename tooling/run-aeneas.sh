#!/usr/bin/env bash
# Regenerate the Aeneas translation of the verified zone.
#
# Pipeline: charon extracts tacenta-wire to LLBC (driving the exact
# rustc nightly it was built against), then aeneas translates the LLBC
# to Lean under verification/Verification/Generated/. The generated
# file is committed; verification/ is the lake package that builds it
# against the Aeneas Lean library (same nightly, same Lean toolchain).
#
# Toolchain: prebuilt nightly binaries from the AeneasVerif releases,
# expected in $AENEAS_TOOLS (default ~/tools/aeneas-nightly). Pin both
# tools and the lakefile require to the SAME nightly date — charon's
# LLBC format, aeneas, and the Aeneas Lean library move together.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

TOOLS="${AENEAS_TOOLS:-$HOME/tools/aeneas-nightly}"
for bin in charon aeneas; do
  if [ ! -x "$TOOLS/$bin" ]; then
    echo "missing $TOOLS/$bin — download the pinned nightly release" >&2
    echo "(see docs/decisions/0006 for the pin and source)" >&2
    exit 1
  fi
done

for crate in tacenta-wire tacenta-state tacenta-directory-core; do
  (cd "crates/$crate" && "$TOOLS/charon" cargo --preset=aeneas -- --package "$crate")
  llbc="$(echo "$crate" | tr - _).llbc"
  "$TOOLS/aeneas" -backend lean -dest verification/Verification/Generated "$llbc"
done
echo "regenerated verification/Verification/Generated/{TacentaWire,TacentaState,TacentaDirectoryCore}.lean"
echo "now build it: cd verification && lake build"
