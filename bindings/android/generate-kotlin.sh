#!/usr/bin/env bash
# Generate the Kotlin bindings from a host build of tacenta-ffi.
#
# One recipe for the two places that need the generated Kotlin: build-aar.sh
# (what ships) and the conformance run's JVM program (what the release run
# exercises), so the two cannot drift apart in bindgen options.
#
# Usage: generate-kotlin.sh <debug|release> <out-dir>
# Builds tacenta-ffi for the host in that profile, then writes the bindings
# under <out-dir>/uniffi/tacenta_ffi/. The host library that was built stays
# at target/<profile>/libtacenta_ffi.{dylib,so}, which is what a JVM run
# points jna.library.path at.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

profile=${1:?debug or release}
out=${2:?output directory}
crate=tacenta-ffi

case "$profile" in
  debug) flag="" ;;
  release) flag="--release" ;;
  *) echo "profile must be debug or release, not $profile" >&2; exit 2 ;;
esac

# The host library is only for uniffi-bindgen to read component metadata
# from; it is never shipped. The release profile strips symbols (docs/
# artifacts.md, item 5), and on Linux that removes the very symbols uniffi's
# `--library` mode reads, so bindgen would emit no bindings. Disable
# stripping for this one build; the shipped per-ABI libraries (built by
# build-aar.sh) stay stripped.
# shellcheck disable=SC2086
CARGO_PROFILE_RELEASE_STRIP=none cargo build --quiet $flag -p "$crate"
# The host library is a .dylib on macOS and a .so on Linux; pick whichever
# exists without tripping `set -e` on the one that does not.
hostlib=""
for candidate in "target/$profile/libtacenta_ffi.dylib" "target/$profile/libtacenta_ffi.so"; do
  [ -f "$candidate" ] && hostlib="$candidate" && break
done
if [ -z "$hostlib" ]; then
  echo "no host library built for uniffi-bindgen" >&2
  exit 1
fi
# --no-format: ktlint is only cosmetic and is not always installed.
mkdir -p "$out"
# shellcheck disable=SC2086
cargo run --quiet -p tacenta-uniffi-bindgen -- generate --no-format \
  --library "$hostlib" --language kotlin --out-dir "$out"
# The one hand-written source (the inbound Flow) travels with the generated
# Kotlin, so every consumer — the .aar, the conformance run, the reference —
# compiles it from the generated tree and none needs a source root of its own.
# Copy it beside the generated file rather than at a guessed path: where
# uniffi nests the package differs by invocation.
generated=$(find "$out" -name 'tacenta_ffi.kt' | head -1)
[ -n "$generated" ] || { echo "no generated Kotlin under $out" >&2; exit 1; }
cp "$(git rev-parse --show-toplevel)"/bindings/android/sugar/*.kt "$(dirname "$generated")/"
