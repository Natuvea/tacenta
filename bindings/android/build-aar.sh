#!/usr/bin/env bash
# Build the Tacenta Android SDK as a distributable .aar.
#
# Compiles tacenta-ffi as a shared library for the four Android ABIs, generates
# the UniFFI Kotlin bindings, and assembles them with Gradle into
# bindings/android/dist/tacenta.aar.
#
# The result is what an app declares as a dependency, so an Android app gets
# end-to-end-encrypted messaging with one artifact. Requires the Android SDK and
# NDK (ANDROID_HOME / ANDROID_NDK_HOME, or the standard macOS location), the
# Rust Android targets, and protoc on PATH (the protobuf code generation needs it).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

crate=tacenta-ffi
lib=libtacenta_ffi.so
out=bindings/android/dist
staging=bindings/android/.staging

sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
ndk="${ANDROID_NDK_HOME:-$(ls -d "$sdk"/ndk/* 2>/dev/null | tail -1)}"
if [ ! -d "$ndk" ]; then
  echo "Android NDK not found; set ANDROID_NDK_HOME" >&2
  exit 1
fi
host=$(ls "$ndk/toolchains/llvm/prebuilt" | head -1)
bin="$ndk/toolchains/llvm/prebuilt/$host/bin"

# The minimum API level the bindings target. 24 matches the Gradle minSdk.
api=24

# Rust target -> the ABI directory name Android expects inside the .aar.
targets=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android)
abis=(arm64-v8a armeabi-v7a x86_64 x86)
# The NDK's clang wrapper name differs from the Rust triple for 32-bit ARM.
clangs=(aarch64-linux-android armv7a-linux-androideabi x86_64-linux-android i686-linux-android)

echo "==> Ensuring rustup targets"
for t in "${targets[@]}"; do rustup target add "$t" >/dev/null; done

echo "==> Building the shared library for each ABI"
rm -rf "$staging" "$out"
for i in "${!targets[@]}"; do
  t="${targets[$i]}"
  clang="$bin/${clangs[$i]}${api}-clang"
  # cargo reads the linker and cc from these per-target variables; the NDK's
  # clang wrapper is what knows the sysroot and API level.
  upper=$(echo "$t" | tr 'a-z-' 'A-Z_')
  under=$(echo "$t" | tr '-' '_')
  env "CARGO_TARGET_${upper}_LINKER=$clang" \
      "CC_${under}=$clang" \
      "AR_${under}=$bin/llvm-ar" \
      cargo build --quiet --release -p "$crate" --target "$t"
  mkdir -p "$staging/jniLibs/${abis[$i]}"
  cp "target/$t/release/$lib" "$staging/jniLibs/${abis[$i]}/$lib"
done

echo "==> Generating the Kotlin bindings"
# Any ABI's library would do since the API is identical; the recipe in
# generate-kotlin.sh builds one for the host so the tool can load it, and is
# the same recipe the conformance run's JVM program uses.
bash bindings/android/generate-kotlin.sh release "$staging/kotlin"

echo "==> Assembling the .aar with Gradle"
mkdir -p bindings/android/lib/src/main
rm -rf bindings/android/lib/src/main/java bindings/android/lib/src/main/jniLibs
cp -R "$staging/kotlin" bindings/android/lib/src/main/java
cp -R "$staging/jniLibs" bindings/android/lib/src/main/jniLibs

( cd bindings/android && ./gradlew --quiet :lib:assembleRelease )

mkdir -p "$out"
cp bindings/android/lib/build/outputs/aar/lib-release.aar "$out/tacenta.aar"
# The licence and third-party notices travel INSIDE the artifact, not only beside
# it: MPL-2.0 requires the notice and a source-availability offer to reach a
# recipient of the executable form. Inject them into the .aar (a zip) before the
# checksum, and also leave copies beside it for convenience.
root="$(git rev-parse --show-toplevel)"
zip -qj "$out/tacenta.aar" \
  "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES" "$root/tooling/notices/MPL-SOURCE-OFFER.txt"
cp "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES" "$root/tooling/notices/MPL-SOURCE-OFFER.txt" "$out/"
# The checksum a consumer verifies and, with the key in the environment, the
# signature Maven Central requires (decision 0090). Computed
# after the notices are embedded so the checksum covers the final artifact.
(cd "$out" && shasum -a 256 tacenta.aar | tee SHA256SUMS)
bash tooling/sign-artifacts.sh "$out/tacenta.aar"
rm -rf "$staging"
echo "==> Done: $out/tacenta.aar"
