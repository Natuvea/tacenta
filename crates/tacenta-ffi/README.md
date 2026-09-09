# tacenta-ffi

Foreign-language bindings for the Tacenta client, via
[UniFFI](https://mozilla.github.io/uniffi-rs/). Exposes the
[`tacenta-client`](../tacenta-client) facade to Swift and Kotlin from one Rust
surface — both the pre-account path (`connect` / `send` / `receive`) and the
account flow (`signUp` / `signIn` / `find`).

Every call is **async**: Swift sees `async throws` methods and Kotlin
`suspend fun`s. Each call spawns its work on the crate's own two-worker
runtime and awaits the task, so the work runs on the SDK's threads, and a
call the app cancels detaches from a task that still completes. The
`SecureStore` callbacks an app implements are synchronous and run on those
threads, from inside a call.

## Swift usage

The account flow — sign up a user, sign in (which provisions the device under
the account's handle), find another user, and message them:

```swift
try await signUp(accounts: "127.0.0.1:4722", apiKey: apiKey,
                 username: "alice", password: "…")

let config = AccountConfig(
    directory: "127.0.0.1:4720", relay: "127.0.0.1:4721",
    accounts: "127.0.0.1:4722", provisioning: "127.0.0.1:4723",
    identifier: "alice", device: 1)
// The API key and the password travel apart from the config, so the config
// can be printed or logged without carrying either.
let client = try await Client.signIn(config: config, apiKey: apiKey, password: "…")

if let bob = try await client.find(username: "bob") {
    try await client.send(to: bob.address, message: Data("hello".utf8))
}
for message in try await client.receive() {
    print("\(message.from.user): \(message.plaintext)")
}
```

`exportIdentity()` returns the device secret to persist; reconnect with
`Client.signInWithIdentity` to keep the same bound key across restarts. The
contact list itself lives on the foreign side — `find` returns a `Contact`,
which the app stores however it likes. The pre-account `Client.connect` (raw
handle, no tenant) is still exported.

The Kotlin surface mirrors this: `signUp(...)`, `Client.signIn(config)`,
`client.find("bob")`.

## Generating the bindings

Build the library, then run the workspace's bindgen crate against it:

```bash
cargo build -p tacenta-ffi
cargo run -p tacenta-uniffi-bindgen -- generate \
  --library target/debug/libtacenta_ffi.dylib \
  --language swift --out-dir <out>          # or --language kotlin
```

This emits `tacenta_ffi.swift` (or `.kt`), a C header, and a modulemap.
The Rust surface is verified by `tests/binding.rs` (a full conversation
through the exported functions); the generated Swift is verified to compile
on macOS with `swiftc -typecheck`.

## Packaged Swift SDK (xcframework)

For distribution, [`bindings/swift/`](../../bindings/swift) packages this
crate as a Swift Package. `build-xcframework.sh` builds the static library
for macOS, iOS device, and the iOS simulator, generates the bindings once,
and assembles `dist/TacentaFFI.xcframework`; `Package.swift` wraps that
framework plus the generated Swift as the `Tacenta` library, and
`examples/quickstart` is a runnable app that reaches **hosted Tacenta**
through the `Tenant` handle (`connect` / `signUp` / `signIn`, decision
record 0090: no host or port in the app). The release pipeline builds the
xcframework and compiles the package and example on every push, so the
packaging cannot rot. The built xcframework
is a large binary artifact (~140 MB) — it is git-ignored and, for a
release, zipped and hosted like the CLI binaries, with `Package.swift`'s
`binaryTarget` switched from `path:` to `url:` + `checksum:`.

The Android `.aar` and its example are the Kotlin-side equivalent, still
downstream.
