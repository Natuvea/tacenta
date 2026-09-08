#!/usr/bin/env bash
# Build the Tacenta Swift SDK as a distributable xcframework.
#
# Compiles tacenta-ffi as a static library for macOS, iOS device, and the
# iOS simulator; generates the Swift bindings once; and assembles an
# xcframework plus the Swift source into bindings/swift/dist/.
#
# The result is what a Package.swift binaryTarget points at, so an app
# depends on Tacenta with a single Swift Package reference. Requires the
# Xcode command-line tools and protoc (the protobuf code generation needs it).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

crate=tacenta-ffi
lib=libtacenta_ffi.a
out=bindings/swift/dist
staging=bindings/swift/.staging

# The three Apple slices an app needs: Mac (Apple Silicon), a real iPhone,
# and the simulator. Each is a separate rustc target.
targets=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)

echo "==> Ensuring rustup targets and llvm-tools"
# llvm-objcopy, for the bitcode removal below, ships with the toolchain's
# llvm-tools component rather than with Xcode.
rustup component add llvm-tools >/dev/null 2>&1 || true
objcopy="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | awk '/^host:/ {print $2}')/bin/llvm-objcopy"
[ -x "$objcopy" ] || { echo "llvm-objcopy not found at $objcopy; rustup component add llvm-tools" >&2; exit 1; }
for t in "${targets[@]}"; do
  rustup target add "$t" >/dev/null
done

echo "==> Building the static library for each target"
# Match Package.swift's minimum platforms so the linker does not warn that
# the objects target a newer OS than the package.
export MACOSX_DEPLOYMENT_TARGET=12.0
export IPHONEOS_DEPLOYMENT_TARGET=15.0
for t in "${targets[@]}"; do
  cargo build --quiet --release -p "$crate" --target "$t"
done

echo "==> Generating the Swift bindings"
rm -rf "$staging" "$out"
mkdir -p "$staging/Headers"
# Bindgen reads a built library to emit the Swift source, C header, and
# modulemap; any one slice will do since the API is identical.
cargo run --quiet -p tacenta-uniffi-bindgen -- generate \
  --library "target/aarch64-apple-darwin/release/$lib" \
  --language swift --out-dir "$staging/swift"

# xcframework wants the header + a module.modulemap in one Headers dir.
cp "$staging/swift/tacenta_ffiFFI.h" "$staging/Headers/"
cp "$staging/swift/tacenta_ffiFFI.modulemap" "$staging/Headers/module.modulemap"

echo "==> Assembling the xcframework"
mkdir -p "$out"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-darwin/release/$lib" -headers "$staging/Headers" \
  -library "target/aarch64-apple-ios/release/$lib" -headers "$staging/Headers" \
  -library "target/aarch64-apple-ios-sim/release/$lib" -headers "$staging/Headers" \
  -output "$out/TacentaFFI.xcframework"

# The generated Swift wrapper ships alongside the binary framework; the
# Swift Package compiles it as a source target that links the framework.
mkdir -p "$out/Sources/Tacenta"
cp "$staging/swift/tacenta_ffi.swift" "$out/Sources/Tacenta/Tacenta.swift"
# The hand-written sugar over it (the inbound AsyncSequence) ships beside it.
cp bindings/swift/Sources/Tacenta/*.swift "$out/Sources/Tacenta/"

# What a package consumer downloads (decision 0090): the slices with their debug and local symbols stripped
# (the exported symbols an app links against stay), zipped as SwiftPM
# expects a binaryTarget, with the checksum `Package.swift` names beside it
# and a SHA-256 of the zip; tooling/sign-artifacts.sh adds a signature when
# the key is in the environment.
# Under the release profile's LTO, rustc embeds LLVM bitcode in every object
# of a static library (it is how crates take part in the LTO), and that
# bitcode is most of the archive: about 80 MB of a slice against 17 MB once
# it is gone, for the same linked app. Nothing downstream reads it (Apple
# retired bitcode with Xcode 14), so each slice is unpacked, the sections
# removed, and the archive rebuilt, then the debug and local symbols go too.
echo "==> Removing bitcode and stripping the slices"
for slice in "$PWD/$out"/TacentaFFI.xcframework/*/"$lib"; do
  work=$(mktemp -d)
  (cd "$work" && ar x "$slice" && for o in *.o; do
     "$objcopy" --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline "$o"
   done && xcrun libtool -static -no_warning_for_no_symbols -o "$slice" ./*.o)
  rm -rf "$work"
  strip -S -x "$slice"
done
rm -f "$out/TacentaFFI.xcframework.zip"
# Notices travel INSIDE the packaged artifact (MPL-2.0 requires the notice and a
# source-availability offer to reach a recipient of the executable form): place
# them in the .xcframework before it is zipped, so a SwiftPM consumer of the zip
# receives them. The checksum below then covers the final artifact.
root="$(git rev-parse --show-toplevel)"
cp "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES" "$root/tooling/notices/MPL-SOURCE-OFFER.txt" \
  "$out/TacentaFFI.xcframework/"
(cd "$out" && ditto -c -k --keepParent TacentaFFI.xcframework TacentaFFI.xcframework.zip)
(cd "$out" && swift package compute-checksum TacentaFFI.xcframework.zip > TacentaFFI.xcframework.zip.checksum)
(cd "$out" && shasum -a 256 TacentaFFI.xcframework.zip | tee SHA256SUMS)
# Also leave copies beside the zip for convenience.
cp "$root/LICENSE" "$root/THIRD_PARTY_NOTICES" "$root/tooling/notices/MPL-SOURCE-OFFER.txt" "$out/"
bash tooling/sign-artifacts.sh "$out/TacentaFFI.xcframework.zip"
du -sh "$out/TacentaFFI.xcframework" "$out/TacentaFFI.xcframework.zip"

rm -rf "$staging"
echo "==> Done: $out/TacentaFFI.xcframework"
