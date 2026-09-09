# The artifacts

What a release builds for the SDK heads, how big it is, and how a consumer
checks it (decision 0090). The CLI
binaries have their own note in the CLI publish workflow and
`docs/releasing.md`; this is about the packages.

## The release profile

`Cargo.toml` sets one release profile for everything that ships:

| Setting | Value | Why |
|---|---|---|
| `lto` | `fat` | Whole-program optimisation across every crate. Measured on the macOS slice: an app linking the FFI library is 2.75 MB against 3.19 MB without it. |
| `codegen-units` | `1` | The rest of that gain; slower to compile, which a release build can afford. |
| `strip` | `symbols` | The CLI and the Android `.so` files are stripped by the linker. A static library is not linked, so the xcframework build strips its slices itself (below). |
| `panic` | `unwind` (the default) | UniFFI catches a panic at the boundary and reports it to Swift and Kotlin as an internal error; `abort` would end the host app instead. Left at the default on purpose. |
| `overflow-checks` | `true` for tacenta-core's crates | tacenta-core sets this on its own release profile, but a dependency takes the root workspace's profile, so the product restates it for those packages. |

## The xcframework

`bindings/swift/build-xcframework.sh` builds a static library for macOS,
iOS and the iOS simulator, generates the Swift, assembles
`dist/TacentaFFI.xcframework`, and then makes it fit to download:

1. **Bitcode removed.** Under LTO, rustc embeds LLVM bitcode in every object
   of a static library, and it is most of the archive: about 80 MB of a slice
   before, 26 MB after, for the same linked app. Nothing reads it (Apple
   retired bitcode in Xcode 14). Each slice is unpacked, the `__LLVM`
   sections removed with the toolchain's `llvm-objcopy`, and the archive
   rebuilt.
2. **Symbols stripped** (`strip -S -x`): debug and local symbols go, the
   exported symbols an app links against stay.
3. **The bindgen kept out.** The `uniffi-bindgen` entrypoint used to be a
   binary of the FFI crate, and the Cargo feature it needs pulled the whole
   generator (clap, goblin, the UDL parser, the templates) into the library
   an app links, about a fifth of it. It is `crates/uniffi-bindgen` now.
4. **Zipped as SwiftPM wants a `binaryTarget`** (`ditto -c -k --keepParent`),
   with `swift package compute-checksum` written beside it as
   `TacentaFFI.xcframework.zip.checksum`, a `SHA256SUMS`, and, when the
   signing key is in the environment, `TacentaFFI.xcframework.zip.asc`.

Measured on 2026-09-05, after all three: a slice is 9.8 MB against 49 MB
before, the xcframework 28 MB against 140 MB, and its zip 10 MB. The release
pipeline builds all of this and keeps `dist/` as a workflow artifact, so the
zip and its checksum exist for every commit; publishing them is the gated step
below.

Once hosted, `Package.swift` switches its `binaryTarget` from `path:` to

```swift
.binaryTarget(
    name: "TacentaFFI",
    url: "https://tacenta.com/dl/sdk/TacentaFFI-<version>.xcframework.zip",
    checksum: "<the .checksum file's contents>"
)
```

and SwiftPM refuses a download whose checksum differs.

## The `.aar`

`bindings/android/build-aar.sh` builds the four ABIs' shared libraries
(stripped by the profile), generates the Kotlin (which carries the one
hand-written source, the inbound Flow, from `bindings/android/sugar`), and
assembles `dist/tacenta.aar`, then writes
`SHA256SUMS` and, with the key, `tacenta.aar.asc`. The release pipeline
keeps `dist/` as a workflow artifact.

## Signing

`tooling/sign-artifacts.sh` writes a detached, ASCII-armoured GPG signature
beside each file it is given, from a key in the environment:

- `TACENTA_SIGNING_KEY`: the ASCII-armoured private key
  (`gpg --armor --export-secret-keys <id>`);
- `TACENTA_SIGNING_PASSPHRASE`: its passphrase.

Both are repository secrets the CI jobs pass through. Without them the
script says the artifacts are unsigned and exits 0, so a build without the
key still produces everything else; a publish step that requires signatures
checks for the `.asc` files. The public half belongs at
`tacenta.com/.well-known/tacenta-signing-key.asc` and on a keyserver
(`keys.openpgp.org`), which is what Maven Central checks against.

Creating the key, once, by a person, is a manual release step.

## Maven Central

Publishing the `.aar` there needs, beyond the signature, a Central Portal
account, a verified namespace, a user token, and a POM carrying the licence
Central requires. The step-by-step is the
release procedure in `docs/releasing.md`; the Gradle side (the `maven-publish`
and signing plugins on `lib`) is a small change made once those exist.

## What stays gated

Everything above is built by the release pipeline. Hosting the zip and the
`.aar`, and pushing to Maven Central, are publications and are not yet done
(decision 0090). When they are, the release workflow gains an upload of
`dist/` beside the CLI binaries, `Package.swift` takes the URL and checksum,
and the Gradle publication is added. The human-gated steps that open it — the
Maven Central account and namespace, and the GPG key — are manual release
steps.
