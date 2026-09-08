# 0052 — the Swift SDK ships as an xcframework Swift Package

## Decision

Package `tacenta-ffi` as a distributable Swift Package under
`bindings/swift/`. `build-xcframework.sh` builds the static library for
three Apple slices — macOS (Apple Silicon), iOS device, iOS simulator —
generates the UniFFI Swift bindings once, and assembles
`dist/TacentaFFI.xcframework`. `Package.swift` wraps that framework and the
generated Swift as the `Tacenta` library and builds a runnable `quickstart`
example. A `swift-package` CI job, on a macOS runner, builds the
xcframework and compiles the package + example on every push.

The FFI gains the TLS constructors this requires: `sign_up_tls` and
`Client.sign_in_tls`, which trust the public web PKI — so a packaged app
reaches hosted Tacenta (`tacenta.com`) directly, not just a local server.

## Context

Decision 0029 landed the first binding (UniFFI Swift/Kotlin) and CI already
type-checked the generated Swift. But type-checking a `.swift` file is not
a shippable SDK: an app developer needs a binary framework they can add to
Xcode, and the exported surface only spoke the plaintext local path, so it
could not talk to the hosted service the website points people at. Closing
both is what turns "the bindings compile" into "a developer can build on
hosted Tacenta."

## Considered

- **A separate SDK repository.** Decision 0029 imagined the artifact and
  example living in their own repos. Kept in-tree instead: the package must
  build from *this* commit's FFI, and an in-tree CI job is what keeps it
  from rotting. A public mirror can be split out later without moving the
  source of truth.
- **Committing the built xcframework.** It is ~140 MB of static libraries —
  a build output, not source. Git-ignored; a release zips and hosts it (as
  the CLI binaries already are under `/dl/`) and flips `Package.swift`'s
  `binaryTarget` from `path:` to `url:` + `checksum:`.
- **Exposing `ClientTls` to the foreign side.** Overbuilt for the hosted
  case, which is always a public CA. The TLS constructors take just a
  `serverName` and use web-PKI trust internally; certificate pinning can be
  added later if a deployment with a private CA needs it.

## Why

The three-slice xcframework is the standard Apple distribution unit, and
building all three in CI establishes a useful fact: the whole stack —
`tacenta-core`, `ring` (via rustls, for the TLS path), libcrux —
cross-compiles cleanly to iOS, so there is no native-toolchain blocker
for mobile. The example is a
package target, not a doc snippet, so it is compiled on every push and
cannot drift from the exported API.

## What would reopen this

- The Android `.aar` and its example (the Kotlin-side equivalent, still
  downstream).
- UniFFI async export, so Swift sees `async` methods instead of blocking
  calls on a background thread.
- Session-state persistence (0051) is not yet on the FFI surface;
  exporting `export_state` / `sign_in_with_state` is a natural follow-up so
  mobile apps get durable sessions too.
- A signed, hosted release of the xcframework (the `url:` + `checksum:`
  form) with a versioned release workflow.
