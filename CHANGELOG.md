# Changelog

One section per release tag, newest first; the section for the next tag
sits at the top under its version before the tag exists, and
`tooling/check-versions.sh` refuses a tag without one (`docs/releasing.md` has
the order of a release). Dates are the day the tag was pushed. Earlier tags (v1.0.0 to v1.1.2) predate this file; the
commits carry their story.

## v1.11.5 (2026-09-05)

- The Swift DocC reference is published at `tacenta.com/dl/reference/swift/`.
  No SDK change.

## v1.11.4 (2026-09-05)

- Release plumbing for the Swift DocC reference. No SDK change.

## v1.11.3 (2026-09-05)

- Release plumbing for the Swift DocC reference. No SDK change.

## v1.11.2 (2026-09-05)

- The Swift head's generated reference (DocC) is built from the module's
  symbol graph with `docc` directly. No SDK change.

## v1.11.1 (2026-09-05)

- Release plumbing only, no SDK change: the generated Swift DocC and Kotlin
  Dokka references are best-effort, so a documentation-tool failure on a
  runner does not block publishing the binaries or running the conformance
  suite. Carries the same SDK as v1.11.0.

## v1.11.0 (2026-09-05)

- `inbound` on every head: a client's messages one at a time as they
  arrive, `receive` flattened. Rust gets a `Stream` (`Client::inbound`),
  TypeScript an async iterator (`for await (const m of client.inbound())`),
  Swift an `AsyncSequence` (`for try await message in client.inbound()`),
  Kotlin a `Flow` (`client.inbound().asFlow()`); on Swift and Kotlin the
  `Inbound` object's `next()` is the call underneath. `receive` is
  unchanged. The conformance transcript shows a message taken through the
  stream on all three SDK heads.
- `tacenta init <typescript|swift|kotlin|rust> [directory]` scaffolds an
  app with your API key in place and a README that says how to build the
  SDK from a checkout and run it.
- The release places DocC of the Swift package and Dokka of the Kotlin
  bindings under `tacenta.com/dl/reference/{swift,kotlin}/`, beside rustdoc
  and TypeDoc.
- The packages are built to ship (`docs/artifacts.md`): one release profile
  with LTO, and the xcframework's slices without their bitcode and symbols,
  9.8 MB each against 49 (the xcframework 28 MB against 140, its zip 10 MB);
  the bindgen tool is kept out of the library; the xcframework zip, its SwiftPM checksum, and `SHA256SUMS` for
  it and the `.aar` are produced on every build, with a GPG signature when
  the key is configured. The bindgen entrypoint is
  `cargo run -p tacenta-uniffi-bindgen`.
- Every crate is `publish = false` through the workspace, and the
  workspace's own dependencies carry version requirements, ready for the
  day one is published.
- On every head: `restoreOutcome` after a sign-in says whether restored
  sessions are in
  use or were discarded as a rollback; a sealed state is bound to
  the address it was sealed for and refused, as `identityMismatch`, for
  another (the format is v6, v5 still opens); a secure store that
  cannot be reached yet is its own kind, `storeUnavailable`, so a locked
  Keychain or Keystore is not mistaken for tampering; and the
  store's counter must advance on every send, with one store per client. The Rust `attach_secure_store` returns a `Result`.
- The four TCP services serve every connection under a cap
  (`TACENTA_MAX_CONNECTIONS`), a handshake bound (relay) or idle bound
  (directory, accounts, provisioning), and OS TCP keepalive, so a flood or
  a stalled peer is bounded.

## v1.10.0 (2026-09-05)

- A message over the relay's limit is refused before any ratchet step as
  `InvalidArgument`, as is a device number the protocol cannot carry; a
  rewritten state blob is refused rather than trusted for its own count;
  the account config and the account service's replies redact their
  secrets when printed; discovery errors carry neither credentials nor
  unbounded document text; the document fetch follows no redirect and
  sends no cookie; a vouched-for document with a plaintext carriage off
  loopback is refused unless the caller allows it; the TypeScript head
  validates the device number and the message type; the test harness is
  kept out of the package; a cancelled or released receive ends with the
  call, and a blocking secure-store callback does not stall the process.
  The READMEs say where state lives, that it is exported after
  every send and receive, what to do on `State`, and what the Android
  sample's counter does and does not defend against.

## v1.9.0 (2026-09-05)

- A pending `receive` no longer holds the client: on every head it waits
  for the relay's push outside the client's turn and polls only when mail
  may be waiting, so a `send` on the same client from another task goes
  through meanwhile. The conformance conversation sends while a receive is
  pending on all three SDK heads. The Rust client exposes the signal as
  `Client::mail()`.
- `docs/releasing.md` records the release procedure.

## v1.8.0 (2026-09-04)

- The Swift and Kotlin heads are asynchronous: every call is `async throws`
  in Swift and a `suspend fun` in Kotlin, and `receive` awaits the next
  message rather than parking a thread. Each call runs on the SDK's own
  threads and completes even if the app cancels it, and a `receive` a
  caller abandons keeps its batch for the next call. A pending `receive`
  still holds the client, so a `send` on the same client from another task
  waits for it; the surface grid's `receive` row says so.
- One version for every package, carried by the tree and checked against
  the tag: the workspace, the npm package and the Android library all say
  the release they belong to, and this changelog.

## v1.7.0 (2026-09-04)

- Typed errors, the same fifteen kinds on every head: Rust `Error::kind()`,
  TypeScript's `TacentaError.kind`, Swift's `ClientError` cases, Kotlin's
  `ClientException` subclasses. The kinds are a section of the surface
  manifest and of the grid on tacenta.com/sdk/.
- The accounts protocol gains a `RateLimited` reply, so a throttled sign-in
  is no longer reported as a refused password; the relay's refusals reach
  the app as `NotFound`, `RateLimited` and `InvalidArgument`.
- The conformance conversation provokes three kinds against the live
  service and names the kind it got.

## v1.6.0 (2026-09-04)

- The release conformance run drives the Swift Package and the generated
  Kotlin as well as the CLI and the TypeScript head, each over TCP and the
  WebSocket carriage; the transcript is assembled from the heads in a fixed
  order.
- The CLI publish places the SDK surface manifest, stamped with the tag, at
  tacenta.com/dl/sdk/, and the generated reference (rustdoc, TypeDoc) at
  tacenta.com/dl/reference/, for the site's /sdk/ pages to render and link.

## v1.5.0 (2026-09-04)

- The Swift and Kotlin heads gain the tenant handle: `Tenant.connect` with
  the API key, then `signUp` and `signIn`, with no host or port in the app;
  the server and device arguments default.
- The transport ends a dropped client's reader and socket; the conformance
  transcripts are listed at tacenta.com/dl/conformance/.

## v1.4.0 (2026-09-04)

- The SDK surface is a manifest every head is tested against, rendered as
  `sdk/SURFACE.md`.
- Every release tag runs the published CLI over TCP and the WebSocket
  carriage and the TypeScript head against hosted Tacenta, keeping the
  transcript at tacenta.com/dl/conformance/.
- The CLI's next-step signposts point at the site's SDK section.

## v1.3.0 (2026-09-04)

- The gateway carries the four services over WebSockets at
  `/v1/ws/{directory,relay,accounts,provisioning}`, and the service document
  names the carriage.
- The client compiled to WebAssembly with the TypeScript head on it,
  `sdk/typescript`, reaches the services from browsers and Node.

## v1.2.0 (2026-09-04)

- The server publishes a service document at `/.well-known/tacenta` and the
  client's `Tacenta` handle discovers the four services from it; the CLI's
  `try` and `chat` go through the handle.
