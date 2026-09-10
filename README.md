# Tacenta

**Verifiable end-to-end encrypted messaging for your app.**

Website: [tacenta.com](https://tacenta.com) ·
[Quickstart](https://tacenta.com/quickstart/) ·
[SDK](https://tacenta.com/sdk/) ·
[Assurance](https://tacenta.com/assurance/)

One Rust protocol core, shared by the server and every client binding, with its
security-critical zones machine-checked against a Lean spec, and a recipe to
rerun the proofs yourself. Where most messaging stacks ask you to trust the
implementation, Tacenta ships the proofs and the commands to check them.

The core is [tacenta-core](https://github.com/Natuvea/tacenta-core): a
standalone, clean-room cryptographic engine written from the published Signal
Protocol specifications, with its own proofs. Tacenta is its first consumer,
adding the directory, delivery, accounts, transport, and the SDK heads a
product needs.

## Using it

One protocol core, exposed through several heads so an application uses its
native language:

- **TypeScript / JavaScript** (browsers and Node): `@tacenta/sdk`, the client
  compiled to WebAssembly. See [sdk/typescript/README.md](sdk/typescript/README.md).
- **Swift and Kotlin**: native bindings over the same Rust client via UniFFI.
  See [crates/tacenta-ffi/README.md](crates/tacenta-ffi/README.md).
- **Rust**: the high-level client crate directly (`tacenta-client`): the tenant
  handle, connect / send / receive.

Every head is tested against one surface manifest, so the heads stay at parity;
[sdk/SURFACE.md](sdk/SURFACE.md) is the rendered grid. It is not yet packaged
for a registry; today you build from source: each head's linked README above has
its build steps, or run the Rust end-to-end demo (**Running the demo** below).

## Assurance

The point of a verification-first stack is that you do not take its word for it.
[docs/reproduce.md](docs/reproduce.md) is the single ordered recipe to rebuild
the proofs and rerun the checks from a clean checkout (the model-layer proofs
and the committed Rust-to-Lean translation's T1/T3 proofs reproduce on any
machine with the pinned toolchains; only *regenerating* that translation needs
the pinned Aeneas release, whose tag and archive digest tacenta-core's
`CLAIMS.md` states, and which ships for linux-x86_64 only), and the story is
kept honest across four documents:

- [docs/claims.md](docs/claims.md) — proven versus tested versus assumed,
  claim by claim, enforced by CI.
- [docs/threat-model.md](docs/threat-model.md) — what the system defends,
  against whom, and its stated non-goals (metadata, signup throttling, the
  authorization logic not yet proven; sign-in is rate-limited).
- [docs/verification-tcb.md](docs/verification-tcb.md) — the trusted
  computing base of the proofs: what a green proof assumes (Lean kernel,
  Charon/Aeneas, the spec being the intended one) and what it does not cover.
- [docs/side-channels.md](docs/side-channels.md) — where Tacenta's own code
  makes a timing choice (auth dummy-verify, high-entropy token lookup), the
  reasoning written out rather than left implicit.

**What is proven today.** Three zones are proven correct as written: the Rust is
translated to Lean (Charon/Aeneas) and machine-checked against the
specification: the v1 envelope codec (panic-freedom on arbitrary input plus a
full round trip), both delivery state machines (session and multi-device user),
and the **directory trust core** — trust on first use holds on the shipped
`register_core`/`rotate_core`, so a bound device cannot be silently reassigned
to a different identity. The security-critical logic not yet refined (authorized
rotation/recovery, the relay's per-device isolation, account/provisioning
authorization) is spec-proven and its Rust is written-to-match, tested, fuzzed,
and differential-conformance-tested against the spec. `docs/claims.md` draws the
line precisely.

**Status: pre-alpha.** The API is not yet stable and nothing is packaged for a
registry.

## Layout

```
spec/        Lean 4 protocol specification and proofs (lake project)
contracts/   Conformance vectors extracted from the spec (CI-checked)
crates/      Rust workspace
  tacenta-wire/   Wire formats — the verified zone (Aeneas-friendly subset)
  tacenta-state/  Delivery state machines — the verified zone
  tacenta-relay/  Cryptographically blind message router (server core)
  tacenta-directory-core/ Directory trust core (register/rotate) — verified zone
  tacenta-directory/ Public-key directory (identity keys, prekey bundles)
  tacenta-transport/ Framed TCP/TLS server + client for the four services,
                     and the WebSocket carriage of the same framing
  tacenta-core/   Protocol engine + crypto integration (client)
  tacenta-accounts/ Control-plane identity: tenants (username / email /
                    password, argon2id) and users (username / password), API keys
  tacenta-discovery/ The service document a server publishes and a client
                    reads to find the four services (decision 0090)
  tacenta-client/ High-level client SDK: the tenant handle, connect / send /
                  receive
  tacenta-ffi/    Swift + Kotlin bindings for the client, via UniFFI
  tacenta-server/ The server binary: directory + relay over one store
  tacenta-gateway/ HTTP control plane: tenant signup, API keys, the service
                   document
  tacenta-cli/    The `tacenta` command: try, chat, contexts, keys
  tacenta-echo/   Echo-bot reference agent: keeps its identity, echoes mail
  tacenta-demo/   Runnable end-to-end demonstration
  tacenta-wasm/   The client compiled to WebAssembly, for the TypeScript head
sdk/typescript/ @tacenta/sdk: the TypeScript head on the client (browsers, Node)
sdk/surface.json The SDK surface manifest every head is tested against; SURFACE.md
                 is its rendered parity grid
tooling/     Repo gates
bindings/    The Swift and Kotlin heads over the FFI crate
verification/ The Rust-to-Lean refinement proofs
docs/        Decision records, claims ledger, threat model, reproduction recipe
assets/      Brand assets
```

## Running the demo

```bash
cargo run -p tacenta-demo
```

Starts a real server in the same process over a shared directory — the
directory service and the relay server — then has two clients register
their keys over the directory socket, authenticate to the relay, look each
other up, and drive an end-to-end encrypted conversation over real TCP,
printing each step and the ciphertext the server sees.

## Running the server

```bash
cargo run -p tacenta-server
```

Binds four services over one shared store and serves until interrupted,
printing each address: the **directory** (public keys), the **relay**
(message routing), the **account** service (tenant/user signup and sign-in),
and **provisioning** (a signed-in user binds its device into the directory
under its handle). Configuration comes from the environment, all optional:

- `TACENTA_BIND` — bind address (default `127.0.0.1`)
- `TACENTA_DIRECTORY_PORT` — directory service port (default `4720`)
- `TACENTA_RELAY_PORT` — relay server port (default `4721`)
- `TACENTA_ACCOUNTS_PORT` — account service port (default `4722`)
- `TACENTA_PROVISIONING_PORT` — provisioning service port (default `4723`)
- `TACENTA_DATA_DIR` — persist state here across restarts; loaded on start,
  saved on Ctrl-C (default: none, state is in memory only)
- `TACENTA_SNAPSHOT_SECS` — also snapshot on this interval, not only on
  shutdown, bounding crash loss to one interval (needs `TACENTA_DATA_DIR`)
- `TACENTA_TLS_CERT` / `TACENTA_TLS_KEY` — PEM certificate and PKCS#8 key;
  set both to serve TLS on every port (default: none, plaintext TCP)

The account and provisioning services carry plaintext passwords and tokens,
so serve them over TLS in any real deployment. Accounts (tenants, users, API
keys, sessions) snapshot to `TACENTA_DATA_DIR` alongside the directory and
relay, so they survive a restart; a durable store (versioned, incremental)
is later work.

Persistence saves the whole state on graceful shutdown; a crash loses work
since the last clean stop (crash-consistent persistence is future work).
TLS encrypts the transport and authenticates the server; message content is
end-to-end encrypted underneath regardless, so TLS is defence in depth.

## Running the echo bot

```bash
TACENTA_ECHO_IDENTITY=echo.key cargo run -p tacenta-echo
```

Connects to a running server as an ordinary client and echoes every message
back to its sender — a live end-to-end check anyone with a client can run,
and the reference agent identity. With `TACENTA_ECHO_IDENTITY` set it saves
its identity to that file on first run and reuses it after, so it keeps the
same address and bound key across restarts (a peer who verified it stays
verified). Configuration comes from the environment, all optional:

- `TACENTA_DIRECTORY` / `TACENTA_RELAY` — server addresses (defaults
  `127.0.0.1:4720` / `127.0.0.1:4721`)
- `TACENTA_ECHO_USER` / `TACENTA_ECHO_DEVICE` — the bot's identity (defaults
  `+echo` / `1`)
- `TACENTA_ECHO_IDENTITY` — file to persist the identity secret in (default:
  none, a fresh identity each run)

## Building

```
cargo test --workspace        # Rust workspace
cd spec && lake build         # check the specification (no sorry)
```

Toolchains: Rust (via rustup), Lean 4 (via elan; version pinned in
`spec/lean-toolchain`), protoc.

## Trademarks and non-affiliation

Tacenta is not affiliated with or endorsed by Signal Messenger LLC or the
Signal Foundation. It implements published Signal Protocol specifications via
an independent, clean-room implementation. See [TRADEMARKS.md](TRADEMARKS.md).
