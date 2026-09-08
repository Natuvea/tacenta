#!/usr/bin/env bash
# The Kotlin head's reference (decision 0090): Dokka over the Kotlin
# UniFFI generates plus the hand-written file beside it, as a plain JVM
# build, so the release workflow needs no Android SDK to document the API.
#
# Usage: build-reference.sh <out-dir>
# Generates the Kotlin from a host build of tacenta-ffi (generate-kotlin.sh)
# unless TACENTA_KOTLIN_BINDINGS already names it, then runs Dokka through
# the wrapper in this directory.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

out=${1:?output directory}
if [ -z "${TACENTA_KOTLIN_BINDINGS:-}" ]; then
  bash bindings/android/generate-kotlin.sh release target/kotlin
  export TACENTA_KOTLIN_BINDINGS="$PWD/target/kotlin"
fi
(cd bindings/android && ./gradlew -p reference -q dokkaHtml)
rm -rf "$out"
mkdir -p "$(dirname "$out")"
cp -R bindings/android/reference/build/dokka/html "$out"
echo "==> Done: $out ($(du -sh "$out" | cut -f1))"
