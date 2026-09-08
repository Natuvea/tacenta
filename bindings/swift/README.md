# Tacenta Swift SDK

The Tacenta client, packaged as a Swift Package for macOS and iOS. It wraps
[`tacenta-ffi`](../../crates/tacenta-ffi) (UniFFI) as an xcframework, so an
app depends on end-to-end-encrypted messaging with one package reference
(decision record 0052).

## Build the framework

```bash
./build-xcframework.sh
```

This builds the static library for macOS, iOS device, and the iOS
simulator, generates the Swift bindings, and assembles
`dist/TacentaFFI.xcframework` plus `dist/Sources/Tacenta/Tacenta.swift`.
Requires the Xcode command-line tools and `protoc` on `PATH`. The `dist/`
output is git-ignored — it is a ~140 MB build artifact, not source.

## Use it

`Package.swift` exposes the `Tacenta` library. Add the package to an app,
then reach hosted Tacenta over TLS:

```swift
import Tacenta

let tenant = try await Tenant.connect(apiKey: apiKey)
try await tenant.signUp(username: "alice", password: password)
let client = try await tenant.signIn(username: "alice", password: password)

if let bob = try await client.find(username: "bob") {
    try await client.send(to: bob.address, message: Data("hello".utf8))
}
```

`examples/quickstart` is the full runnable version (the Swift analogue of
`tacenta try`):

```bash
./build-xcframework.sh
swift run quickstart tct_your_key_here
```

Every call is `async throws`, and the work runs on the SDK's own threads,
so awaiting from the main actor is fine. `receive()` awaits the next
message; a task can sit in it while another task sends on the same client.
`inbound()` is the same one message at a time, an `AsyncSequence`:

```swift
Task {
    for try await message in client.inbound() {
        show(message.from, String(decoding: message.plaintext, as: UTF8.self))
    }
}
```

Run one such loop per client: a message goes to whichever `next` is
waiting. The sequence ends only by throwing, and it holds the client for
as long as the loop runs.

`conformance` is the package's third target: the conversation the release
conformance run makes through this SDK against hosted Tacenta on every tag
(decision 0090), with `TACENTA_API_KEY` in the environment and
`TACENTA_DOCUMENT_URL` to point it at another server:

```bash
TACENTA_API_KEY=tct_your_key_here swift run conformance
```

## Errors

Every call throws `ClientError`, an enum with one case per kind and the
detail in `reason`. The kinds are the same on every head and described in
`sdk/SURFACE.md`; a case may be added, so switch with a default.

```swift
func signIn() async {
    do {
        client = try await tenant.signIn(username: "alice", password: password)
    } catch ClientError.SignInRefused {
        showPasswordPrompt()
    } catch {
        showError(error)
    }
}
```

## Rollback-resistant state (`SecureStore`)

`exportState` / `connectWithState` persist a session, but their anti-rollback
generation is plaintext an attacker who can rewrite the file could forge
(decision 0078). The **sealed** pair — `exportStateSealed` /
`connectWithStateSealed` / `signInWithStateSealed` — authenticates the state
under a key you keep in the Keychain, so a rewritten file is refused on restore.
That closure is only as strong as the key's hiding place: it must live in the
Keychain, never beside the state blob.

You implement the generated `SecureStore` protocol — a wrapping **key** and a
monotonic **rollback counter**, both Keychain-held so a file-rewriter cannot
reach them. **This is a starting point, not a finished implementation** — set the
Keychain accessibility to a `...ThisDeviceOnly` class, decide your
backup/migration story, and review it before shipping:

```swift
import Security

final class KeychainSecureStore: SecureStore {
    private let service = "com.example.tacenta"

    func wrapKey() throws -> Data {
        if let existing = try read("state-wrap-key.v1") { return existing }
        var key = Data(count: 32)
        let ok = key.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard ok == errSecSuccess else {
            throw ClientError.State(reason: "secure RNG failed")
        }
        try write("state-wrap-key.v1", key)
        return key
    }

    // The rollback counter: a big-endian UInt64 in the Keychain. It must only
    // ever increase and must not be reachable by whoever can rewrite the state
    // file — that is exactly what makes it catch a same-generation rollback.
    func rollbackCounter() throws -> UInt64 {
        guard let data = try read("state-rollback-counter.v1") else { return 0 }
        return data.withUnsafeBytes { UInt64(bigEndian: $0.load(as: UInt64.self)) }
    }

    func bumpRollbackCounter() throws -> UInt64 {
        let next = try rollbackCounter() + 1
        try write("state-rollback-counter.v1", withUnsafeBytes(of: next.bigEndian) { Data($0) })
        return next
    }

    private func read(_ account: String) throws -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var out: CFTypeRef?
        switch SecItemCopyMatching(q as CFDictionary, &out) {
        case errSecSuccess: return out as? Data
        case errSecItemNotFound: return nil
        case let status: throw ClientError.State(reason: "keychain read \(status)")
        }
    }

    private func write(_ account: String, _ value: Data) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // Update in place, adding only when absent: a delete-then-add would
        // leave no counter at all if the app died between the two, and a
        // missing counter reads as zero, which is every rollback accepted.
        // Not synced to iCloud, not restored to another device.
        let update: [String: Any] = [kSecValueData as String: value]
        switch SecItemUpdate(base as CFDictionary, update as CFDictionary) {
        case errSecSuccess: return
        case errSecItemNotFound: break
        case let status: throw ClientError.State(reason: "keychain update \(status)")
        }
        var item = base
        item[kSecValueData as String] = value
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ClientError.State(reason: "keychain write \(status)")
        }
    }
}
```

Attach the store once (turning on per-send rollback protection), then use the
sealed pair with the same store instance across restarts:

```swift
let store = KeychainSecureStore()
try await client.attachSecureStore(store: store) // every send now commits the counter
let blob = try await client.exportStateSealed()  // persist `blob`
// …later, on restart, through the same tenant handle:
let client = try await tenant.signInWithStateSealed(
    username: "alice", password: password, state: blob, store: store)
```

(`Client.connectWithStateSealed` and `Client.signInWithStateSealed` do the
same at the address layer, for a caller holding a `Config` or
`AccountConfig` rather than a handle.)

Five rules that follow from how the seal works:

- **Export after every send and receive**, and keep only the latest blob.
  The store's counter moves on each; a restore of any older blob is refused
  as a rollback, and the client then drops its sessions and starts them
  afresh on next contact. Exporting once at launch is not enough.
- **Where the blob lives**: it carries private keys, so an app-private file
  with data protection (`.completeUntilFirstUserAuthentication`) or, for a
  small blob, the Keychain; never a backup that leaves the device.
- **On `State` from a restore, do not delete the blob.** Only a refused
  authenticator means the file was altered, and the reason says so. A
  Keychain that is not yet available (before first unlock) is
  `StoreUnavailable`, a different case: have your `SecureStore` throw it
  for exactly that, and retry after the device unlocks. A blob sealed on
  another user's or device's behalf is refused as `IdentityMismatch`
  before its identity can be registered under the wrong address.
- **Read `restoreOutcome()` after a sealed sign-in.** `.sessionsDiscarded`
  means the state was older than one already seen: its sessions were
  dropped and the identity kept, so conversations re-establish on next
  contact. Tell the user; the blob stays.
- **One store per client.** A second `attachSecureStore` is refused, and a
  store whose counter stops advancing fails the next send as `State`.

A `send` the app cancels has an unknown outcome: the SDK finishes it, but
the result is not delivered. Re-sending is safe; the peer may see the
plaintext twice.

## Releasing

For distribution, zip `dist/TacentaFFI.xcframework`, host it, and switch
`Package.swift`'s `binaryTarget` from `path:` to `url:` + `checksum:` (from
`swift package compute-checksum`). A versioned release workflow is future
work.
