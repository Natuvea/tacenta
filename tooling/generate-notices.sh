#!/usr/bin/env bash
# Generate THIRD_PARTY_NOTICES for the shipped artifacts (decision 0090).
# cargo-about renders the licence text of every third-party crate the
# product ships, across every target triple listed in tooling/notices/about.toml.
#
# One superset file covers the Rust graph shared by the CLI, the Swift
# xcframework, the Android .aar, and the npm package's WebAssembly module. The
# per-artifact additions that are not Rust crates are appended by the build
# scripts that know them: JNA (Apache-2.0) for Android, and the MPL-2.0 source
# pointer for UniFFI on the native heads.
#
# Usage: generate-notices.sh [out-file]   (default: THIRD_PARTY_NOTICES)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

out=${1:-THIRD_PARTY_NOTICES}
command -v cargo-about >/dev/null 2>&1 || {
  echo "cargo-about not installed: cargo install cargo-about --locked --features cli" >&2
  exit 1
}
cargo about generate --config tooling/notices/about.toml \
  tooling/notices/notices.hbs -o "$out"
# Components cargo-about's Rust graph does not cover: our own tacenta-core
# (Apache-2.0), the MPL-2.0 source offer for UniFFI, and JNA (a Java/Maven
# dependency of the Android artifact).
cat tooling/notices/additions.txt >> "$out"
echo "==> wrote $out ($(wc -l < "$out") lines)"
