# 0029 — the first SDK binding: UniFFI (Swift / Kotlin)

> The WebAssembly head (sdk/typescript) has since been built.

## Decision

`tacenta-ffi` binds the [`tacenta-client`](../../crates/tacenta-client)
facade to Swift and Kotlin through [UniFFI](https://mozilla.github.io/uniffi-rs/).
A `Client` UniFFI object exports `connect` / `send` / `receive` / `address`;
`Config`, `Address`, and `Message` are records; errors flatten to a
`ClientError`.

Two shape decisions:

- **UniFFI first, not web/wasm.** The web binding is blocked: browsers
  cannot open raw TCP, and the client's transport is TCP (a WebSocket
  transport, decision-record-0023 territory, is unbuilt). UniFFI targets
  native platforms where the client's TCP works, and covers Swift *and*
  Kotlin from one surface, so it is the first binding that can actually run.
- **A blocking foreign surface.** The exported `Client` holds its own
  tokio runtime and `block_on`s each async client call, so the foreign API
  is plain synchronous methods — no async-runtime bridging, no `Send`-across-
  await constraints on the FFI boundary. `receive` blocks until mail
  arrives; a caller runs it on a background thread. UniFFI async export is
  the ergonomic upgrade later.

## Verification

The Rust surface is exercised by `tests/binding.rs` — a full two-client
conversation through the exact exported functions (`Client::connect`,
`send`, `receive`), driven synchronously as a foreign caller would. The
generated Swift is checked to compile: the `swift` CI job on a macOS
runner builds `tacenta-ffi`, generates the Swift
bindings, and `swiftc -typecheck`s them. The type-check wires the generated
modulemap explicitly (`-Xcc -fmodule-map-file=…`); a bare `-I` leaves the
FFI module unresolved and the check silently passes over undefined symbols.

## Considered

- **A hand-written C ABI (cbindgen).** Lower-level and more work per
  platform, and not the plan (UniFFI/wasm). UniFFI generates idiomatic Swift
  and Kotlin from one Rust surface with error and object handling built in.
- **Async UniFFI export.** More ergonomic (Swift `async`), but it requires
  the exported futures to be `Send` and a runtime bridge. The blocking
  surface is simpler and lands cleanly; async is a follow-on once the
  surface is proven.
- **Bind `tacenta-client` directly.** UniFFI needs its own crate anyway
  (the `#[uniffi::export]` types, the cdylib crate-type, the bindgen bin);
  keeping `tacenta-ffi` separate leaves `tacenta-client` a clean Rust
  library and gives the bindings one crate to build.

## Naming

Same rule as the facade — no stuttering (decision record 0028). The Swift
reads `Client.connect(config:)`, `client.send(to:message:)`,
`client.receive()`; data types are `Config`, `Address`, `Message`. No path
segment repeats its neighbour.

## What would reopen this

- **A packaged artifact + example app.** The binding generates sources; a
  published `xcframework` (Swift) and `.aar` (Kotlin), and an example app
  consuming them, are downstream work in their own repos.
- **Async export and a Mac CI runner.** Moving from blocking to UniFFI
  async, and adding a macOS runner to compile (and run) the Swift in CI,
  are the two upgrades that make this production-grade.
- **The web binding.** Still blocked on a WebSocket transport; once that
  exists, a wasm-bindgen binding of the same facade is the web SDK.
