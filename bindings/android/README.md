# Tacenta Android SDK

The Tacenta client, packaged as an Android library (`.aar`). It wraps
[`tacenta-ffi`](../../crates/tacenta-ffi) (UniFFI) so an app depends on
end-to-end-encrypted messaging with one artifact, the Kotlin counterpart of the
[Swift SDK](../swift) (decision record 0052).

## Build

```bash
./build-aar.sh
```

This cross-compiles the FFI for the four Android ABIs (arm64-v8a, armeabi-v7a,
x86_64, x86), generates the Kotlin bindings, and assembles
`dist/tacenta.aar`. It needs the Android SDK and NDK (`ANDROID_HOME` /
`ANDROID_NDK_HOME`, or the standard macOS location), the Rust Android targets,
`protoc` on `PATH`, and a JDK (the Gradle wrapper here fetches Gradle itself).

## State

Built and checked. `build-aar.sh` produces a `dist/tacenta.aar` of about 7.8 MB
containing the compiled Kotlin (`classes.jar`) and `libtacenta_ffi.so` for all
four ABIs. The release pipeline builds it on every push and asserts each ABI
and the compiled bindings are present, so the packaging cannot rot.

Two conventions worth knowing:

- The FFI error field is `reason`, on both bindings: UniFFI maps an error enum
  to a Kotlin exception, where the name `message` would collide with
  `Throwable.message`.
- The Kotlin bindings are generated with `--no-format`, since formatting is
  cosmetic and ktlint is not always installed. The recipe is
  `generate-kotlin.sh`, shared with the conformance run.

`conformance/` is the release conformance run's Kotlin head (decision 0090): a JVM program over the same generated Kotlin, bound through JNA to
the FFI library built for the host, so it needs no emulator. From this
directory, after `generate-kotlin.sh debug target/kotlin` at the repository
root:

```bash
TACENTA_API_KEY=tct_your_key_here ./gradlew -p conformance -q run
```

`TACENTA_DOCUMENT_URL` points it at another server. The release pipeline compiles it against the `.aar`'s Kotlin on every push.

## Use it

Once built, an app declares the `.aar` and uses the same surface the Swift SDK
exposes: a `Tenant` handle per tenant (`connect`, `signUp`, `signIn`,
`signInWithState`, `signInWithStateSealed`), and the `Client` it hands out
(`find`, `send`, `receive`, `inbound`, `exportState`). The generated Kotlin mirrors the
Swift naming. No host or port appears in an app: the handle discovers the
services from the server's document (decision 0090).

```kotlin
// Every call that touches the network is a suspend fun.
val tenant = Tenant.connect(apiKey)
tenant.signUp("alice", password)
val client = tenant.signIn("alice", password)

client.find("bob")?.let { bob ->
    client.send(bob.address, "hello".toByteArray())
}
```

A self-hosted server is `Tenant.connect(apiKey, "chat.example.org")`. A
local development server is reached from an emulator by forwarding the
gateway's port and the four service ports to the host, so that from the
emulator they are loopback, which is the only place a plaintext document is
accepted from:

```bash
for p in 4780 4720 4721 4722 4723; do adb reverse tcp:$p tcp:$p; done
```

then `Tenant.connectVia(apiKey, "http://127.0.0.1:4780/.well-known/tacenta")`.
The `AccountConfig` constructors on `Client` remain for callers that know
their addresses.

Every call is a `suspend fun`, and the work runs on the SDK's own threads,
so any dispatcher will do. `receive()` suspends until the next message; a
coroutine can sit in it while another sends on the same client.
`inbound()` is the same one message at a time, collected as a `Flow`:

```kotlin
scope.launch {
    client.inbound().asFlow().collect { message ->
        show(message.from, message.plaintext.decodeToString())
    }
}
```

Run one such collector per client: a message goes to whichever `next` is
waiting. The flow ends only by throwing or when its collector is
cancelled, and it holds the client for as long as it runs.

## Errors

Every call throws `ClientException`, a sealed class with one subclass per
kind and the detail in `reason`. The kinds are the same on every head and
described in `sdk/SURFACE.md`; a subclass may be added, so `when` with an
`else`. A `SecureStore` implementation should throw
`ClientException.State`, or `ClientException.StoreUnavailable` when the
Keystore cannot be reached yet; anything else it throws is reported as
`State`, with the reason.

```kotlin
try {
    tenant.signIn("alice", password)
} catch (e: ClientException.SignInRefused) {
    showPasswordPrompt()
}
```

## Rollback-resistant state (`SecureStore`)

`exportState` / `connectWithState` persist a session, but their anti-rollback
generation is plaintext an attacker who can rewrite the file could forge
(decision 0078). The **sealed** pair — `exportStateSealed` /
`connectWithStateSealed` / `signInWithStateSealed` — authenticates the state
under a key you keep in the Android Keystore, so a rewritten file is refused on
restore. That closure is only as strong as the key's hiding place: it must be
Keystore-backed, never stored beside the state blob.

You implement the generated `SecureStore` interface — a wrapping **key** and a
monotonic **rollback counter**. The Keystore does not hand back raw symmetric key
bytes, so the idiom is to store both in `EncryptedSharedPreferences`, whose master
key *is* Keystore-held. **This is a starting point, not a finished
implementation** — review the master-key scheme, backup rules
(`android:allowBackup`, which must exclude these prefs so the counter cannot be
restored to an older value) and threat model before shipping:

```kotlin
import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

class KeystoreSecureStore(context: Context) : SecureStore {
    private val prefs = EncryptedSharedPreferences.create(
        context,
        "tacenta_secure",
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    override fun wrapKey(): ByteArray {
        prefs.getString(KEY, null)?.let { return Base64.decode(it, Base64.NO_WRAP) }
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(KEY, Base64.encodeToString(key, Base64.NO_WRAP)).apply()
        return key
    }

    // The rollback counter: a Long that only increases, kept where a
    // file-rewriter cannot lower it. This is what catches a same-generation
    // rollback of an older sealed state.
    override fun rollbackCounter(): ULong =
        prefs.getLong(COUNTER, 0L).toULong()

    override fun bumpRollbackCounter(): ULong {
        val next = prefs.getLong(COUNTER, 0L) + 1L
        prefs.edit().putLong(COUNTER, next).commit()
        return next.toULong()
    }

    private companion object {
        const val KEY = "state-wrap-key.v1"
        const val COUNTER = "state-rollback-counter.v1"
    }
}
```

Attach the store once (turning on per-send rollback protection), then use the
sealed pair with the same store instance across restarts:

```kotlin
val store = KeystoreSecureStore(context)
// From a coroutine: these are suspend funs.
client.attachSecureStore(store)                // every send now commits the counter
val blob = client.exportStateSealed()          // persist `blob`
// …later, on restart:
val client = tenant.signInWithStateSealed("alice", password, blob, store)
// (Client.connectWithStateSealed(config, blob, store) is the address-layer form.)
```

What this sample does and does not defend against, stated plainly: the
counter lives in `EncryptedSharedPreferences`, app-private storage in the
same class as the state file it guards. An attacker who can rewrite the
state file can as easily keep an old copy of the preferences file alongside
it, and restoring both together rolls the counter back with the blob. The
sample therefore defeats a rewrite of the state file alone, which is the
common case (a backup restored, a sync tool, a copied directory), and not an
attacker with full write access to the app's private storage; that needs
the hardware's rollback resistance (StrongBox, on devices that have it).
Decision 0078's status records the same limit.

Five rules that follow from how the seal works:

- **Export after every send and receive**, and keep only the latest blob.
  The store's counter moves on each; a restore of any older blob is refused
  as a rollback, and the client then drops its sessions and starts them
  afresh on next contact. Exporting once at launch is not enough.
- **Where the blob lives**: it carries private keys, so `filesDir` through
  `EncryptedFile`, excluded from backup; never external storage.
- **On `State` from a restore, do not delete the blob.** Only a refused
  authenticator means the file was altered, and the reason says so. A
  Keystore that needs the user first is `StoreUnavailable`, a different
  case: have your `SecureStore` throw `ClientException.StoreUnavailable`
  for exactly that, and retry after unlock. A blob sealed on another
  user's or device's behalf is refused as `IdentityMismatch` before its
  identity can be registered under the wrong address.
- **Read `restoreOutcome()` after a sealed sign-in.**
  `RestoreOutcome.SESSIONS_DISCARDED` means the state was older than one
  already seen: its sessions were dropped and the identity kept, so
  conversations re-establish on next contact. Tell the user; the blob stays.
- **One store per client.** A second `attachSecureStore` is refused, and a
  store whose counter stops advancing fails the next send as `State`.

A `send` the app cancels has an unknown outcome: the SDK finishes it, but
the result is not delivered. Re-sending is safe; the peer may see the
plaintext twice.
