# The SDK surface

Generated from `sdk/surface.json` by `tooling/surface-grid.py`; do not edit.
A cell is the symbol that head exposes for the call, or a dash where the head
does not have it yet, with the gap named beneath the table. Each head's test
suite checks itself against the manifest, so this grid cannot drift from the
code without a test failing (decision 0090).

## Tacenta

One tenant's handle: built from the API key and the server's name, it fetches the service document once and hands out signed-in clients.

| Call | rust | typescript | swift | kotlin |
|---|---|---|---|---|
| connect | `Tacenta::connect` | `Tacenta.connect` | `Tenant.connect` | `Tenant.connect` |
| signUp | `Tacenta::sign_up` | `Tacenta.signUp` | `Tenant.signUp` | `Tenant.signUp` |
| signIn | `Tacenta::sign_in` | `Tacenta.signIn` | `Tenant.signIn` | `Tenant.signIn` |
| signInWithState | `Tacenta::sign_in_with_state` | `Tacenta.signInWithState` | `Tenant.signInWithState` | `Tenant.signInWithState` |
| signInWithStateSealed | `Tacenta::sign_in_with_state_sealed` | - | `Tenant.signInWithStateSealed` | `Tenant.signInWithStateSealed` |
| websocket | `Tacenta::websocket` | - | `Tenant.websocket` | `Tenant.websocket` |

- **signInWithStateSealed**: The TypeScript head has no sealed state yet.
- **websocket**: TypeScript always takes the carriage, so there is no switch.

## Client

One signed-in user on one device.

| Call | rust | typescript | swift | kotlin |
|---|---|---|---|---|
| address | `Client::address` | `Client.address` | `Client.address` | `Client.address` |
| find | `Client::find` | `Client.find` | `Client.find` | `Client.find` |
| send | `Client::send` | `Client.send` | `Client.send` | `Client.send` |
| receive | `Client::receive` | `Client.receive` | `Client.receive` | `Client.receive` |
| inbound | `Client::inbound` | `Client.inbound` | `Client.inbound` | `Client.inbound` |
| restoreOutcome | `Client::restore_outcome` | `Client.restoreOutcome` | `Client.restoreOutcome` | `Client.restoreOutcome` |
| exportState | `Client::export_state` | `Client.exportState` | `Client.exportState` | `Client.exportState` |
| exportStateSealed | `Client::export_state_sealed` | - | `Client.exportStateSealed` | `Client.exportStateSealed` |
| attachSecureStore | `Client::attach_secure_store` | - | `Client.attachSecureStore` | `Client.attachSecureStore` |
| reconnect | `Client::reconnect` | - | - | - |

- **receive**: Awaits the next non-empty batch on every head; inbound is the same one message at a time. A pending receive waits for mail outside the client's turn, so a send on the same client goes through meanwhile.
- **inbound**: Rust: a Stream that borrows the client; TypeScript: an async iterator for `for await`; Swift: an Inbound that is an AsyncSequence; Kotlin: an Inbound with `asFlow()`. A message goes to whichever loop is running, so run one per client.
- **restoreOutcome**: Only the sealed restore and a checkpoint can discard sessions, so on TypeScript, which has neither, it is fresh or resumed.
- **exportState**: The bytes carry private keys: app-private, encrypted at rest, only the latest copy kept, and exported again after every send and receive (a restore of an older copy rewinds sessions and, on the sealed path, is refused).
- **exportStateSealed**: No sealed state on the TypeScript head yet.
- **attachSecureStore**: No secure-store hook on the TypeScript head yet.
- **reconnect**: Every head reconnects on its own with backoff; only Rust exposes the call.

## Inbound

A client's inbound messages one at a time, on the FFI heads; Rust's Stream and TypeScript's async iterator carry their own next.

| Call | rust | typescript | swift | kotlin |
|---|---|---|---|---|
| next | - | - | `Inbound.next` | `Inbound.next` |

- **next**: Rust and TypeScript iterate the stream itself; the Swift and Kotlin sugar is built on this call.

## Errors

Every head raises one error type whose kind an app branches on: Rust `Error::kind()` gives an `ErrorKind` (and `as_str()` its name as the other heads spell it); TypeScript throws `TacentaError` with a `kind` and the detail in `message`; Swift throws `ClientError` with one case per kind and the detail in `reason`; Kotlin throws `ClientException` with one subclass per kind and the detail in `reason`. The kind is the contract and may gain members, so handle the ones you branch on and let the rest fall through; the detail is a string for a log line, not for matching on. Checked by the same tests as the calls.

| Kind | rust | typescript | swift | kotlin |
|---|---|---|---|---|
| Network | `ErrorKind::Network` | `"network"` | `ClientError.Network` | `ClientException.Network` |
| Discovery | `ErrorKind::Discovery` | `"discovery"` | `ClientError.Discovery` | `ClientException.Discovery` |
| UnknownTenant | `ErrorKind::UnknownTenant` | `"unknownTenant"` | `ClientError.UnknownTenant` | `ClientException.UnknownTenant` |
| UsernameTaken | `ErrorKind::UsernameTaken` | `"usernameTaken"` | `ClientError.UsernameTaken` | `ClientException.UsernameTaken` |
| InvalidUsername | `ErrorKind::InvalidUsername` | `"invalidUsername"` | `ClientError.InvalidUsername` | `ClientException.InvalidUsername` |
| WeakPassword | `ErrorKind::WeakPassword` | `"weakPassword"` | `ClientError.WeakPassword` | `ClientException.WeakPassword` |
| SignUpRefused | `ErrorKind::SignUpRefused` | `"signUpRefused"` | `ClientError.SignUpRefused` | `ClientException.SignUpRefused` |
| SignInRefused | `ErrorKind::SignInRefused` | `"signInRefused"` | `ClientError.SignInRefused` | `ClientException.SignInRefused` |
| IdentityMismatch | `ErrorKind::IdentityMismatch` | `"identityMismatch"` | `ClientError.IdentityMismatch` | `ClientException.IdentityMismatch` |
| NotFound | `ErrorKind::NotFound` | `"notFound"` | `ClientError.NotFound` | `ClientException.NotFound` |
| RateLimited | `ErrorKind::RateLimited` | `"rateLimited"` | `ClientError.RateLimited` | `ClientException.RateLimited` |
| ServerFailure | `ErrorKind::ServerFailure` | `"serverFailure"` | `ClientError.ServerFailure` | `ClientException.ServerFailure` |
| State | `ErrorKind::State` | `"state"` | `ClientError.State` | `ClientException.State` |
| StoreUnavailable | `ErrorKind::StoreUnavailable` | `"storeUnavailable"` | `ClientError.StoreUnavailable` | `ClientException.StoreUnavailable` |
| InvalidArgument | `ErrorKind::InvalidArgument` | `"invalidArgument"` | `ClientError.InvalidArgument` | `ClientException.InvalidArgument` |
| Internal | `ErrorKind::Internal` | `"internal"` | `ClientError.Internal` | `ClientException.Internal` |

- **Network**: The network or the transport failed; retry later.
- **Discovery**: The service document could not be fetched or read.
- **UnknownTenant**: The API key selects no tenant.
- **UsernameTaken**: The username is already taken in this tenant.
- **InvalidUsername**: The username is not one the server accepts.
- **WeakPassword**: The password is too weak.
- **SignUpRefused**: A sign-up was refused for another reason: registration is closed, or the handle is reserved.
- **SignInRefused**: The credentials were refused, or the session expired; coarse by design.
- **IdentityMismatch**: The address is bound to a different device identity (trust on first use); also a sealed state offered to a user or device it was not sealed for.
- **NotFound**: The address is not registered.
- **RateLimited**: The server asked for a slower pace: too many failed sign-ins, or the recipient's queue is full. Back off and retry.
- **ServerFailure**: The server could not process the request; nothing was applied. Retry.
- **State**: The persisted state was refused: altered, older than the last send, or its secure-storage key is wrong; whatever else a SecureStore raises surfaces here. Do not delete the blob.
- **StoreUnavailable**: The platform's secure store could not be reached (a Keychain before first unlock, a Keystore that needs the user). Nothing was refused: retry after unlock and keep the blob.
- **InvalidArgument**: The caller's own input was wrong: a malformed address or config, a message over the size limit.
- **Internal**: A protocol or cryptographic failure, or a bug: worth reporting.
