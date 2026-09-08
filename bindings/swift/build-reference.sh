#!/usr/bin/env bash
# The Swift head's reference (decision 0090): DocC over the package,
# transformed for static hosting under tacenta.com/dl/reference/swift/.
#
# Usage: build-reference.sh <out-dir>
# Needs dist/ from build-xcframework.sh (the module compiles against it).
# Builds from the symbol graph `swift build` emits and runs `docc` directly,
# rather than `xcodebuild docbuild -scheme`: the latter needs a full-Xcode
# scheme and destination, while `swift build` and `xcrun docc` are the same
# tools the package already builds with. The output is a self-contained site whose
# links assume the hosting path below.
set -euo pipefail
# Resolve the output path against the caller's directory *before* cd, so a
# relative `reference/swift` lands where the workflow's upload step looks for
# it (the repo root), not under bindings/swift where the build must run.
out=${1:?output directory}
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

cd "$(git rev-parse --show-toplevel)/bindings/swift"
symbols=$(mktemp -d)
trap 'rm -rf "$symbols"' EXIT

[ -d dist/TacentaFFI.xcframework ] || { echo "run build-xcframework.sh first" >&2; exit 1; }

# Emit the module's symbol graph, then let docc render it. No .docc catalog:
# the API reference is generated from the symbols alone, with fallback names.
swift build --target Tacenta \
  -Xswiftc -emit-symbol-graph \
  -Xswiftc -emit-symbol-graph-dir -Xswiftc "$symbols"
graph=$(find "$symbols" -name 'Tacenta.symbols.json' | head -1)
[ -n "$graph" ] || { echo "no symbol graph was produced for Tacenta" >&2; exit 1; }

# Render into a directory docc creates itself, then move it into place: some
# docc versions refuse an --output-path whose parent does not yet exist.
staged=$(mktemp -d)/site
xcrun docc convert \
  --fallback-display-name Tacenta \
  --fallback-bundle-identifier com.tacenta.Tacenta \
  --additional-symbol-graph-dir "$symbols" \
  --output-path "$staged" \
  --transform-for-static-hosting \
  --hosting-base-path dl/reference/swift
# DocC's root page is a redirect to the module; land there directly.
echo '<meta http-equiv="refresh" content="0; url=documentation/tacenta/">' > "$staged/index.html"
rm -rf "$out"
mkdir -p "$(dirname "$out")"
mv "$staged" "$out"
echo "==> Done: $out ($(du -sh "$out" | cut -f1))"
