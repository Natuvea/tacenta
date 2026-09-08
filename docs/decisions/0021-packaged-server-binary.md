# 0021 — a packaged server binary

## Decision

`tacenta-server` is a crate that binds the directory service and the relay
server over one shared directory and serves them, so a client can point at
a running instance (`cargo run -p tacenta-server`). It is a library plus a
thin binary:

- **The library** owns the two server-side crypto verifiers — `IdentityAuth`
  (relay connection auth: read the identity from the shared directory,
  verify the challenge signature) and `PossessionCheck` (registration proof
  of possession) — and a `Server` with `bind` / `serve` split so the actual
  listening addresses are readable before serving forever. The verifiers
  live here because they are the same on every deployment and are what the
  crypto-free transport takes as its injected `Authenticator` / `Possession`.
- **The binary** reads `Config` from the environment (`TACENTA_BIND`,
  `TACENTA_DIRECTORY_PORT` default 4720, `TACENTA_RELAY_PORT` default 4721),
  binds, prints the two addresses, and serves.

The demo now points at this server rather than re-wiring its own: it calls
`Server::bind` on ephemeral ports, spawns `serve`, and acts purely as two
clients. The verifiers exist once, in the server library.

## Considered

- **Put the crypto verifiers in `tacenta-core`.** They are cryptographic,
  and core is the crypto crate — but they are *server-side* (they read the
  directory the server owns and answer the transport's server traits),
  while core is the client engine. Housing them in the server keeps core
  pointed at the client and avoids core depending on the transport.
- **A binary with no library.** Simpler, but then the verifiers and the
  bind/serve logic are untestable except by launching a process, and the
  demo would keep its own copies. The lib+bin split makes the server an
  integration-tested artifact (`tests/pointable.rs`) and gives the demo one
  place to reuse.
- **One port, multiplexed.** Serve both protocols on a single port behind a
  discriminator. The two services already have distinct protocols and
  distinct clients (`DirConnection`, `Connection`); two listeners keep each
  path simple and let a deployment firewall or scale them separately. The
  cost is one extra port, which is cheap.

## Why

The co-location (decision record 0020) proved two services could share one
directory, but that wiring lived in the demo. A real project needs a
server you can actually run and point a client at; packaging it as a
lib+bin turns the wiring into a tested, reusable artifact and collapses the
verifier duplication that had accumulated across the demo and the tests.
`tests/pointable.rs` is the proof: a client registers over the directory,
authenticates to the relay against that registration, routes a message,
and an unregistered device is refused — all against a `Server` bound on
ephemeral ports exactly as a deployment would run it.

## What would reopen this

- **Persistence and graceful shutdown now exist** (decision record 0022):
  the server loads snapshots on `bind` and saves on Ctrl-C. The save is
  whole-state at shutdown only; crash-consistent/periodic persistence
  remains open.
- **Plaintext TCP, no transport security.** WebSocket/TLS (decision record
  0014) would wrap the same frames; the server binds raw TCP today.
- **No operational surface.** No health check, metrics, structured logs, or
  rate limiting. Fine for a demonstrable server; a deployment wants them.
