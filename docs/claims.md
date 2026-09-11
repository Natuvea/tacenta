# Claims

What is proven, what is tested, and what is assumed — kept precise on
purpose. Most claims here are enforced by the public CI on every push: the
specification Lean proofs are rebuilt (no `sorry` in them), the conformance
vectors are regenerated from the specification and diffed, and the Rust test
suite replays them. The refinement proofs over the shipped Rust rebuild in the
verification workflow, not in this repository's `ci.yml`.

**Two classes run outside the public `ci.yml`.** First, the axiom audit:
`spec/Tacenta/Assurance.lean` pins the specification-level theorems with
`#guard_msgs #print axioms` under the CI `spec` build, and
`verification/Verification/Assurance.lean` pins the refinement theorems the
same way, running `#print axioms` on all nineteen headline refinement theorems
so a `sorry` or a widened axiom set is caught. That audit and the refinement
build run in the verification workflow, not in this repository's `ci.yml`;
both reproduce locally (see `reproduce.md`). Second, the Postgres claims:
`crates/tacenta-accounts/tests/pg.rs` is behind the `postgres` feature and
each test returns early without `TACENTA_TEST_DATABASE_URL`. The public `rust`
job here does not exercise the `postgres` feature; the release pipeline supplies a `postgres:16` service container and
runs the DB-backed tests (four account tests, one server test). The local
default `cargo test --workspace` skips them without a database URL; supply the
URL to run them, as the pipeline job does.
Toolchain pins: Lean 4 v4.31.0, Charon/Aeneas nightly 2026.07.22 (decision
record 0006).

## Proven — specification level

Machine-checked in `spec/` about the Lean model itself:

- **Wire format** (`Tacenta.Wire`): big-endian u16/u32 byte encodings
  round-trip (`decodeU16_encodeU16`, `decodeU32_encodeU32`); kind bytes
  round-trip (`Kind.ofByte?_toByte`); and the envelope round trip
  `decode_encode` — every envelope `encode` produces, `decode` returns
  intact, with wrong version, unknown kind, length mismatch, and
  trailing bytes all rejected by construction.
- **Stream framing** (`Tacenta.Wire`, `Stream.lean`): a sequence of
  envelopes, encoded and concatenated, decodes back to exactly that
  sequence (`decodeStream_encodeStream`), resting on the streaming
  single-parse lemma `decodeOne_encode`.
- **Single-device sessions** (`Tacenta.Session`): appends never disturb
  pending messages (`pending_append`); acks never touch the log, never
  rewind, and remove exactly a delivered prefix — no replay, no
  reorder, no loss (`ack?_log`, `ack?_cursor_lt`, `pending_ack?`);
  invalid acks are exact no-ops (`ack?_rejects`).
- **Multi-device users** (`Tacenta.User`): a successful ack changes
  exactly one cursor and nothing else (`ack?_spec`); one device's ack
  never moves another's cursor (`cursorOf_ack?_frame`); user-level
  delivery (minimum cursor) never rewinds (`delivered_ack?`); linking a
  device never un-delivers (`delivered_linkDevice`).
- **The delivery guarantee** (`Tacenta.Delivery`): a message is
  delivered to the user *exactly* when it exists and every device has
  acknowledged past it (`isDelivered_iff`), and once delivered it stays
  delivered under every later append and every later ack
  (`isDelivered_append`, `isDelivered_ack?`) — the emergent
  whole-system property, composed from the per-operation theorems.
  Because the Rust `User::delivered` refines the spec's `delivered`
  (`user_delivered_refines`), the shipped code inherits this guarantee.
- **Directory trust rules** (`Tacenta.Directory`): the store-level
  authorization semantics. **Trust on first use** — whatever a device is
  bound to, `register` leaves it bound to exactly that; a different identity
  cannot displace an existing binding (`register_tofu`). A new device is bound
  (`register_binds_fresh`), the same key refreshes without changing the binding
  (`register_same_keeps`), `register` never touches another device's binding
  (`register_frames`), and `rotate` refuses an unbound device and otherwise
  replaces the binding (`rotate_requires_binding`, `rotate_rebinds`). **Key
  continuity** (decision records 0024/0025) is modelled and proven against an
  abstract, assumed-unforgeable signature check: an *unauthorized* rotation
  cannot move the binding (`rotation_unauthorized_frames`), an authorized one
  rebinds (`rotation_authorized_rebinds`), and an unbound device has no key to
  authorize against (`rotation_auth_requires_binding`) — so, composed with the
  signature's unforgeability (assumed; the implementation is tacenta-core's
  XEdDSA), only the holder of the
  currently-bound key can move a binding. **Lost-key recovery** (0025) is the
  sibling path: a rebind authorized by a pre-provisioned *recovery* key rather
  than the lost identity key — an unauthorized recovery cannot move the binding
  (`recovery_unauthorized_frames`), an authorized one rebinds
  (`recovery_authorized_rebinds`), and a device with no recovery key set cannot
  be recovered (`recovery_requires_key`). **The trust core is now refined to the
  Rust; the authorized-rotation/recovery wrappers are spec-level.** The Rust
  factors the trust decision into pure functions of one device's current binding
  (`register_core` / `rotate_core` in `tacenta-directory-core`), with the
  `HashMap` reduced to trust-irrelevant glue — the `HashMap` is what a
  Charon/Aeneas translation cannot handle, a pure `Option`/byte-compare function
  is not. Those two functions are **translated by Charon/Aeneas and proven to
  refine** the spec's `registerCore` / `rotateCore`
  (`Verification.register_core_refines` / `rotate_core_refines`), so trust on
  first use holds on the *shipped* Rust, not just a model
  (`register_core_tofu_translated`) — the same footing as the wire codec and the
  delivery machines. The spec's `register_matches_core` proves the `HashMap`
  wrapper applies the core faithfully, so the wrapper inherits the core's trust.
  Still spec-level (proven of the model, Rust written to match, tested and
  fuzzed, not yet refined): the *authorized* rotation and recovery (the
  currently-bound key signing the change, `rotation_*` / `recovery_*`), which
  live above the store. The `HashMap` wrapper's cross-device *framing* is also
  checked mechanically by `crates/tacenta-directory/tests/spec_conformance.rs`
  (randomized register/rotate traces differential-tested against a
  spec-transliterated reference).
- **Account session + provisioning authorization** (`Tacenta.Accounts`): the
  anti-impersonation rule (decision records 0034/0035). A freshly issued session
  token validates to its user (`validate_issued`), issuing one changes no other
  token's session (`issue_frames`), a never-issued token authorizes nothing
  (`unissued_validates_none`), and — the load-bearing property — the handle a
  provisioning binds is exactly the *session user's* handle, a function of the
  validated token and never of client input (`provision_handle_from_session`),
  so a client can only provision under the handle its own session authorizes.
  The tokens' unguessability (high-entropy secrets) is assumed; the logic-that-
  derives-the-handle-from-the-session is proven. Also **tenant isolation**
  (0033): users are unique per tenant, not globally, so the same username can
  belong to a user in two tenants and a signup in one never affects another — a
  signup binds its key (`signUp_binds`), refuses a taken one
  (`signUp_rejects_taken`), leaves every other key untouched (`signUp_frames`),
  and two tenants hold the same username independently (`tenant_isolation`).
  Spec-level, like the directory rules above — the Rust is written to match and
  is tested, not yet refined. The tenant-isolation match is checked
  mechanically too: `crates/tacenta-accounts/tests/spec_conformance.rs` drives
  the real `Accounts` store over randomized signup traces against a reference
  model keyed by `(tenant, username)`, asserting binds / rejects-taken /
  framing / isolation hold (differential testing, not a proof).
- **Relay per-device authorization** (`Tacenta.RelayAuth`): a connection may read
  (poll) and advance (ack) only *its own* device's queue. A connection reads its
  own queue (`poll_own`) and no other (`poll_only_own`); it advances its own
  (`ack_own_advances`), cannot advance another's (`ack_only_own`), and advancing
  its own leaves every other device's queue untouched (`ack_frames_others`).
  This is the authorization gate on top of the delivery *semantics*
  (no-replay/no-rewind) already proven in `Session`/`User`. Spec-level.
- **Protocol-layer handshake and ratchet** (`Tacenta.Handshake`,
  `Tacenta.Ratchet`): a model of the protocol layer we consume from
  tacenta-core
  — PQXDH and the Double Ratchet — written from the published protocol
  documents over *abstract* primitives (DH, KEM, and KDFs are type
  parameters; DH commutativity and KEM correctness enter as theorem
  hypotheses, never axioms). Proven of the model: initiator and responder
  derive the same session secret, with and without a one-time prekey
  (`pqxdh_agree`); the published bundle carries public halves only, by
  construction (`bundle_public`); symmetric chains derive each position's
  message key deterministically with a strictly advancing position — a
  position is consumed exactly once, so the machine can never derive the
  same message position twice (`step_key_at`, `step_idx`); chains started
  equal agree at every position (`keys_agree`); the DH-ratchet round trip
  preserves peer agreement — the ping-pong induction step (`ratchet_sync`);
  and a session initialised from the handshake starts in that agreeing
  configuration (`init_facing`). **Spec-only, and scoped deliberately**: no
  Rust in *this* repository is refined against it (decision record
  0075). tacenta-core proves its own implementation against its own Lean
  model, which is a different model on a separate axiom baseline; the two are
  not connected by any theorem. It models in-order delivery (what the relay
  provides; skipped-message keys are future work), and it claims functional
  correctness of the state machine, not cryptographic security — forward
  secrecy and post-compromise security remain with the published protocol
  analyses, outside this repository's claims.

## Proven — implementation level

Machine-checked in `verification/` about the **translated Rust**: the
`tacenta-wire` crate is translated to Lean by Charon/Aeneas (the
translation is committed and reviewed like source), and the following
hold of that translation:

- **`encode.spec`** — the Rust encoder never panics and its output
  agrees byte-for-byte with the specification's encoder, for every
  envelope whose payload is not within 7 bytes of the address space
  (a hypothesis the model needs for 32-bit platforms; no real vector
  reaches it).
- **`decode.spec`** — for **every possible input**, well-formed or
  hostile, the Rust decoder never panics and returns exactly what the
  specification's decoder returns.
- **`encode_decode_roundtrip`** — composed: whatever the Rust encoder
  emits, the Rust decoder returns an envelope equal (under abstraction)
  to the original.
- **`decode_one.spec`** — the translated single-envelope stream parser
  (`decode_one`, the building block of `decode_stream`) never panics on
  any input and agrees with the spec's `decodeOne` under abstraction —
  the parsed envelope and the returned remainder both.
- **`decode_stream.spec`** — the translated `decode_stream` *loop* never
  panics on any byte buffer and agrees with the spec's `decodeStream`
  under abstraction: any buffer decodes to exactly the envelope sequence
  the spec produces, or is rejected. Proven with `loop.spec_decr_nat`
  (measure = remaining bytes, decreasing via `decodeOne_consumes`) on top
  of `decode_one.spec`, with a length bound in the invariant discharging
  the `push` capacity side condition.
- **`encode_stream.spec`** — the translated `encode_stream` *loop*, given
  the total encoded length fits `Usize`, never panics and agrees with the
  spec's `encodeStream` under abstraction: the concatenated per-envelope
  encodings are exactly what the spec produces. Also `loop.spec_decr_nat`
  (measure = remaining envelopes), carrying a running `totalEncodedLen`
  bound in the invariant to discharge `extend_from_slice`'s capacity side
  condition. With this, the **entire wire codec — single envelope and
  stream, both encode and decode — is refinement-proven.**
- Kind conversions refine their spec counterparts in both directions
  (`to_byte_refines`, `from_byte_refines`).
- **Session machine** (`tacenta-state`, generic; proven at the spec's
  envelope type): `new`, `append`, `ack`, and `pending` never panic on
  invariant-satisfying states, preserve the invariant, and agree with
  the specification's operations — acks are accepted exactly when the
  spec accepts, with identical resulting state
  (`session_new_refines`, `session_append_refines`,
  `session_ack_refines`, `session_pending_refines`).
- **User machine, complete** (same crate): `new`, `append`,
  `link_device`, `device_pending`, `delivered` (with a full
  loop-invariant proof of the minimum-cursor fold), and `ack` — none
  panic on invariant-satisfying states, all preserve the invariant, and
  all agree with the specification; `ack` is accepted exactly when the
  spec accepts, with identical resulting state, and rejections
  (including unknown devices) are no-ops (`user_new_refines`,
  `user_append_refines`, `user_link_refines`,
  `user_device_pending_refines`, `user_delivered_refines`,
  `user_ack_refines`). All at the classical-trio axiom baseline.
- **Directory trust core** (`tacenta-directory-core`, translated from the
  leaf crate that holds the trust decision without the `HashMap`):
  `register_core` and `rotate_core` never panic and agree with the spec's
  `registerCore` / `rotateCore` under the byte abstraction
  (`register_core_refines`, `rotate_core_refines`) — including a
  from-scratch `Vec<u8>` `PartialEq::eq` spec (`vec_eq_u8`), since the
  Aeneas library ships only the slice version. The security corollary
  holds of the **shipped** Rust: for a bound device, `register_core`
  leaves the binding exactly as it was, whatever key is presented — trust
  on first use, so an address cannot be silently reassigned
  (`register_core_tofu_translated`); an unbound device cannot be rotated
  (`rotate_core_requires_binding_translated`). The `HashMap`-backed
  `Directory` wrapper is trust-irrelevant glue that the spec's
  `register_matches_core` proves applies this core faithfully. Classical-
  trio axiom baseline.

Axiom audit (via `#print axioms`, at the pins above): `encode.spec`
depends only on Lean's three standard classical axioms (`propext`,
`Classical.choice`, `Quot.sound`). `decode.spec` and the round trip
additionally use `bv_decide` SAT certificates for two byte-order
lemmas, whose checking runs through Lean's compiled evaluator (the
per-declaration `Verification.fromBE2_toNat._native.bv_decide.ax_…` and
`fromBE4` axioms pinned in `Verification/Assurance.lean`, which is what
Lean v4.31.0 reports). **No theorem depends on any `sorry`** — the
handful of sorried lemmas in the upstream Aeneas standard library are
not in our proofs' dependency cone.

## Tested, not proven

- Four conformance vector sets (envelope, session traces, user traces,
  streams) are **generated by the specification's own executable
  definitions**; CI regenerates and diffs them, and the Rust suite
  replays every vector, including the rejection cases.
- The **stream framing** is fully refinement-proven now — both the
  `decode_stream` and `encode_stream` loops (moved to the proven list
  above), on top of the spec-level round trip. Nothing about the wire
  codec remains in the tested-not-proven column; it is proven end to end,
  both directions. (The stream *conformance vectors* still run in CI as a
  cross-check.)
- **End-to-end encryption** (`tacenta-core::crypto`) is exercised by a
  real multi-message conversation test — a protocol session
  (PQXDH with an ML-KEM-1024 prekey, the post-quantum ratchet) whose
  ciphertexts travel through the tacenta wire `encode`/`decode`, in both
  directions, across the initial-message to ratchet-message transition (a
  one-byte type header on the frame carries the type; malformed frames
  are rejected). This demonstrates the *integration* works; it is
  **not** a cryptographic proof, and none is claimed. The in-memory store is the default. Full resumable state — the identity plus live ratchet sessions per peer — serializes via `Client::export_state` and restores via `connect_with_state` / `sign_in_with_state` (decision 0051).
- **Full-stack integration** (`tests/delivery_crypto.rs`): a real E2EE
  conversation routed through `tacenta-relay`, the server component — a
  ciphertext framed in an envelope, serialized by the proven codec,
  enqueued to the recipient device's proven delivery `Session`, drained
  as pending, decrypted, and acknowledged so the cursor advances; then
  replies routed back. Exercises every layer as one system. The relay
  is **cryptographically blind** — it depends only on the wire and
  delivery crates, never on crypto, so it has no code path to a
  plaintext (decision records 0011 per-device queues, 0012 blind
  relay). The client drives the relay entirely over its byte
  request/response protocol (`Send`/`Poll`/`Ack`, decision record 0013),
  whose payloads ride the proven envelope and stream codecs. Wire and
  delivery behavior proven; the crypto is tacenta-core's.
- **Networked capstone with authentication**
  (`tests/networked_conversation.rs`): the same E2EE conversation over a
  **real TCP socket**, now with each client **authenticated to the
  server** — it signs the server's challenge with its identity private
  key, and the server verifies against the device's registered public
  key before serving it (decision records 0014 transport, 0015 auth).
  The relay enforces that a device may only read its own queue (by
  address comparison — it stays blind); a bad signature is rejected at
  the handshake. Crypto + transport + blind relay + the proven wire and
  delivery layers, running as one authenticated networked system.
- **Sign-in rate limiting** (`tacenta-accounts`, `ratelimit`): online password
  guessing is throttled by a sliding window of failed attempts keyed by
  `(tenant, identifier)` — five failures in a minute refuse further attempts
  with `AuthError::RateLimited` before the credential check runs, and a success
  clears the count. Unit-tested (window, ceiling, recovery, key independence)
  and integration-tested through the real store with an injected clock
  (`tests/ratelimit.rs`): a blocked key refuses even the correct password, the
  block lifts after the window, a missing account throttles identically (no
  existence oracle), and locking one account does not lock another. Mechanism,
  tested — not a proof; keyed-by-identifier and existence-oracle-freedom are
  design properties argued in `docs/side-channels.md` (decision record 0042).
- **Session expiry** (`tacenta-accounts`): a session token is valid only for a
  fixed lifetime after sign-in (24h, `SESSION_TTL_SECS`); after that
  `validate_session` returns `None`, exactly as for an unknown token, bounding a
  leaked token's window. Deterministically tested with an injected clock
  (`tests/session_expiry.rs`): valid up to but not including the TTL boundary,
  expired at and after it, measured from issue time, and the expiry survives a
  snapshot/restore round trip. The **Postgres store** enforces the same expiry
  (an `expires_at` column, migration `0002`; `validate_session` filters on it),
  exercised against a real database in `tests/pg.rs`. Refresh/sliding sessions
  are a follow-up (decision record 0043).
- **Session revocation** (`tacenta-accounts`): `revoke_session` invalidates one
  token before its TTL (sign-out / stolen token); `revoke_user_sessions`
  invalidates every token for a user (sign-out-everywhere / compromise response).
  Tested (`tests/session_revocation.rs`): a revoked token stops validating,
  revoking-all clears exactly that user's tokens and no other's, and a fresh
  sign-in afterwards still works — revocation does not lock the account. The
  **Postgres store** carries both revoke paths (a `DELETE` by token hash and by
  user), tested against a real database in `tests/pg.rs` (decision record 0044).
- **Runnable demo** (`tacenta-demo`): `cargo run -p tacenta-demo` starts
  a relay server on a socket and drives the full authenticated E2EE
  conversation between two clients over real TCP, printing each step. A
  smoke test (`demo_runs`) keeps the wiring from rotting.
- **Persistence** (`Relay::snapshot`/`restore`, `Server::snapshot`): the
  relay's queues and cursors survive a restart. The snapshot serializes
  each queue's log through the *proven* stream codec and rebuilds through
  the proven `append`/`ack` API — so a reloaded queue satisfies the same
  invariant the delivery machine is proven to maintain, and an
  out-of-range snapshot is rejected, not forced (decision record 0016).
  The round-trip and a live-after-restore case are tested.
- **Server push** (`tacenta-transport`): when a message is routed to a
  connected device, the server pushes it a notification so it fetches
  immediately rather than polling. The push is a content-free wakeup —
  the client still fetches through the one proven delivery path — and the
  relay gains nothing (it stays blind and synchronous); the transport
  holds the connected-device channels (decision record 0017). Tested
  (`recipient_is_pushed_on_send`) and shown in the demo.
- **Key directory** (`tacenta-directory`, `serialize_bundle`): devices
  publish their public identity key and prekey bundle; a peer looks up a
  bundle to open a session and the server looks up an identity key to
  authenticate — no out-of-band key exchange. The directory stores opaque
  *public* blobs and does no cryptography (decision record 0018); a
  looked-up bundle is proven usable end to end: two clients register, each
  looks up and deserializes the other's bundle, and they hold a conversation
  (`two_clients_hold_a_conversation`, `tacenta-client/tests/conversation.rs`).
- **Registration trust** (`Directory::register` outcome,
  `tests/registration_trust.rs`): admitting a registration takes two
  independent checks — *proof of possession* (the registrant signs a
  challenge with the identity key it submits; the server verifies against
  that key) and *trust on first use* (the directory binds an address to
  its first identity key and rejects a later registration presenting a
  different one; a same-key registration refreshes the bundle). Each check
  turns away one of two attacks — hijacking a bound address, and
  impersonating an identity you do not hold — and the test demonstrates
  both being rejected, one by each layer. The binding check is a
  crypto-free byte comparison in the directory; possession is
  cryptographic and sits with the admitting server (decision record
  0019). Trust on first use trusts whoever registers an address first.
- **Authorized identity rotation** (`Directory::rotate`,
  `tests/identity_rotation.rs`): a bound identity key can be replaced, but
  only by the key that currently controls it — key continuity. Admitting a
  rotation takes proof of possession of the new key plus a signature from
  the *currently bound* key over the new identity; the crypto-free
  `Directory::rotate` then swaps the binding (decision record 0024). The
  test demonstrates a rotation chain A → B → C, a superseded key being
  refused (authorization is checked against the current binding, not a past
  one), and a third party unable to sign with the bound key failing to take
  the address over. The rotation is also on the directory wire protocol (a
  `Rotate` request carrying the two signatures, verified by the same
  injected `Possession` as registration); `tests/networked_rotation.rs`
  drives it over a real socket.
- **Lost-key recovery** (`Directory::set_recovery` / `recovery_key`,
  `SetRecovery` + `Recover` requests, `tests/recovery.rs`): a device
  provisions a recovery key (private half kept offline), authorized by its
  current identity key; if the identity key is later lost, it re-keys by
  authorizing the rotation with the recovery key instead. Recover reuses
  the crypto-free `rotate` — only the authorizing key differs, and that
  check is the server's. `tests/recovery.rs` drives it over a socket: a
  device provisions a recovery key, re-keys with it, and a third party
  holding neither the current identity key nor the recovery key can do
  neither; recovering an address with no recovery key is refused (decision
  record 0025). The recovery keys survive a restart (in the directory
  snapshot). With this the trust model is complete: an address is claimed
  (proof-of-possession + trust-on-first-use), rotated forward (continuity),
  and re-keyable after device loss (recovery) — with no path for a third
  party to take it over. Losing *both* the identity and recovery keys is
  the irreducible floor.
- **Networked directory service** (`serve_directory` / `DirConnection`,
  `tests/networked_directory.rs`): the directory reached over a real TCP
  socket, built as the transport's sibling — a crypto-free
  register/lookup protocol in the directory crate, socket plumbing in the
  transport, and proof-of-possession injected as a `Possession` verifier
  exactly as connection auth is (decision records 0014, 0020). The test
  drives a real client against a real server: a first registration, a
  same-key refresh, both attacks turned away *on the wire* (hijack →
  `Rejected`, impersonation → `PossessionFailed`), and a peer's lookup
  returning a bundle that opens a working encrypted session. The demo
  (`cargo run -p tacenta-demo`) runs both services in one process over a
  single shared directory — registration and lookup go over the socket,
  the relay authenticates against the same store, and there is no
  in-process directory shortcut.
- **Packaged server** (`tacenta-server`, `tests/pointable.rs`): the
  directory service and relay server bound over one shared directory as a
  runnable binary (`cargo run -p tacenta-server`, ports from the
  environment) a client can point at. A lib+bin: the library owns the two
  server-side verifiers (`IdentityAuth`, `PossessionCheck`) and a
  `bind`/`serve` `Server`; the binary is a thin env-configured entrypoint
  (decision record 0021). `tests/pointable.rs` drives a real client
  against a `Server` on ephemeral ports — register over the directory,
  authenticate to the relay against that registration, route a message,
  and an unregistered device refused. The demo now points at this same
  server rather than wiring its own.
- **Server persistence** (`Directory::snapshot`/`restore`, `Server` load +
  shutdown save, `tests/persistence.rs`): with a data directory configured,
  the server loads the directory and relay snapshots on `bind` and writes
  them back on graceful shutdown (Ctrl-C, or an injected stop via
  `serve_until`). The directory snapshot mirrors the relay's (decision
  record 0016): it replays entries through `register`, so a reloaded
  directory keeps the same trust-on-first-use bindings — the reload tests
  confirm a different identity for a restored address is still rejected.
  `tests/persistence.rs` proves the loop end to end: a client registers
  against a running server, the server restarts, and the client then
  authenticates to the new relay *without re-registering* and finds its
  bundle (decision record 0022). With `snapshot_interval` set, the whole
  state is also saved on a timer, not only on shutdown, so a crash loses at
  most one interval (`tests/periodic.rs` reads the on-disk snapshot mid-run,
  without stopping the server, and finds the registration). The save is
  still whole-state; an incremental/durable store (WAL or DB) is future
  work.
- **Transport TLS** (`serve_tls` / `connect_as_tls`, `serve_directory_tls` /
  `connect_tls`, `tls.rs` tests): both protocols run unchanged over TLS —
  the serve/connect paths are generic over the byte stream, and TLS is a
  wrapping layer (rustls with the `ring` provider). The transport tests
  cover a relay and a directory conversation over TLS and confirm a client
  trusting the wrong certificate is refused at the handshake;
  `tacenta-server`'s `tests/tls_server.rs` runs the whole flow (register,
  authenticate, route) over TLS with the real identity crypto, driven by
  `Config.tls`. TLS protects the transport (metadata, server
  authentication) and is *defence in depth* — message content is already
  end-to-end encrypted underneath it, so the claim is "the transport is
  encrypted and the server authenticated," never that TLS secures the
  messages (decision record 0023). Certificate management (rotation, ACME,
  web-PKI trust) and a WebSocket transport are future work.
- **Sender attribution** (`StoredMessage`, `tests/networked_conversation.rs`):
  the relay stamps the *authenticated* sender onto every message it routes,
  so a recipient learns who each delivered message is from — which it needs
  to decrypt, including a first-contact message from a device it has no
  session with yet. The queued unit is `StoredMessage { from, envelope }`;
  `Poll`'s `Delivered` carries these. The sender comes from the
  authenticated connection (unforgeable at the relay), not the payload,
  which stays opaque; it lives *around* the proven envelope, not inside it,
  so the wire codec's proof is untouched, and the snapshot still rides the
  proven envelope encoding per message (decision record 0027). The
  networked test asserts the delivered sender, and the demo prints "from"
  on each decrypt. This is the foundation for a general inbox (receive from
  anyone) and thus the client SDK.
- **Delivered-to-user watermark** (`Request::Delivered` / `DeliveredCount`,
  `tests/delivered.rs`): a client asks the relay how far *all* of a user's
  devices have caught up — the minimum cursor across them, which is the
  `User` machine's proven `delivered` (`user_delivered_refines`) computed
  live on the relay's per-device cursors. The caller supplies its own
  device list; the relay refuses a device that is not the authenticated
  user's (same address-comparison authorization as `Poll`/`Ack`, so it
  stays blind and needs no directory access). Relay unit test checks the
  min and the cross-user refusal; `tests/delivered.rs` drives it over a
  socket (two devices acked 3 and 1 → watermark 1). Same-user only;
  cross-user read receipts are a separate design (decision record 0026).
- **Multi-device fan-out** (`tests/multi_device.rs`): a message to a
  *user* reaches every one of that user's devices. The sender reads the
  user's devices from the directory's per-user index, opens a session
  with each from its published bundle, and sends a distinct ciphertext to
  each device's queue; every device receives and decrypts independently
  over its own connection with server push. This is the payoff of the
  per-device delivery model the `User` machine is proven to describe
  (decision record 0011) — end-to-end encryption is per device, so a
  message to a person is a fan-out, not a broadcast. The "delivered to
  the user once all devices ack" accounting the `User` machine models is
  not yet wired into the live path; the fan-out delivery is.
- **Client SDK facade** (`tacenta-client`, `tests/conversation.rs`): a
  high-level `Client` wrapping identity, the directory, the relay, and
  sessions behind `connect` / `send` / `receive` — the ~200-line demo
  orchestration in a handful of calls, and the surface the platform
  bindings will export (decision record 0028). `tests/conversation.rs`
  drives a full two-client conversation through the facade, including a
  first-contact message the recipient decrypts and attributes without prior
  knowledge of the sender (only possible because of sender attribution).
  All three items this entry once listed as future work have shipped:
  **persistent identity** (`export_state` / `connect_with_state` /
  `sign_in_with_state`, decision record 0051 — the identity *and* the live
  per-peer sessions, so a restart resumes mid-conversation rather than
  re-establishing), **reconnection and backlog drain** (`receive` polls the
  relay before waiting, so a returning client drains what queued while it was
  offline, and a dead connection gets a bounded immediate/1s/2s/4s/8s
  reconnect), and the **trust operations** (`rotate` generates a fresh
  identity, authorizes the directory rebinding with the currently bound key,
  and adopts it — decision record 0024). `connect` without state still
  generates a fresh identity each time, which is the intended behaviour for a
  first run, not a gap.
- **First SDK binding — UniFFI** (`tacenta-ffi`, `tests/binding.rs`): the
  client facade bound to Swift and Kotlin through UniFFI. A `Client` object
  exports `connect` / `send` / `receive`; the surface is blocking (an
  internal tokio runtime + `block_on`), so the foreign side needs no async
  story (decision record 0029). `tests/binding.rs` drives a full
  conversation through the exact exported functions; the generated Swift is
  verified to compile on macOS (`swiftc -typecheck`, exit 0) — CI (Linux)
  covers the Rust build + test, the Swift compile is a local Mac check. Web
  (wasm): the client compiles to WebAssembly (`crates/tacenta-wasm`) over
  the WebSocket carriage the gateway serves, and `sdk/typescript` is the
  TypeScript head on it, with an end-to-end test in Node run by the
  release pipeline (decision 0090); not yet published to a registry.
  A packaged xcframework / `.aar`, async export, and an example app are
  downstream work.
- Style gates: rustfmt and clippy at `-D warnings`.

## Assumed — the trusted base

- **The cryptography is tacenta-core's, in full.** All confidentiality,
  integrity, and authentication come from the pinned `tacenta-core`
  dependency (decision record 0075). **This repository writes no
  cryptography and proves none**: our proofs cover the wire format and the
  delivery state machines and say nothing about crypto.
- **Underneath tacenta-core, the primitives are third-party and trusted.**
  X25519 (`x25519-dalek`), ML-KEM (`libcrux-ml-kem`), SHA-256, HMAC and the
  AEAD are dependencies, and tacenta-core's own proofs treat them as opaque at
  the boundary. Nobody in either repository verifies them.
- **tacenta-core is not trusted wholesale, and it is not verified wholesale
  either.** It carries its own machine-checked proofs at three tiers, over named
  verified zones rather than the whole library, under stated
  preconditions rather than unconditional totality. Its `CLAIMS.md` and
  `LIMITATIONS.md` are the documents that say which is which. Treating it as
  fully verified is as wrong as treating it as unexamined.
- The Lean 4 kernel and standard library (v4.31.0).
- The classical axioms above, plus the two per-declaration `bv_decide`
  reflection axioms for the SAT certificates noted (the compiled evaluator
  is in the trusted base for those two lemmas).
- **Translation faithfulness**: that Charon and Aeneas correctly model
  the semantics of the Rust they translate, and that the Aeneas
  standard library's models of Rust primitives (vectors, slices,
  scalar arithmetic) are faithful. This is the load-bearing assumption
  of the implementation-level claims.
- The Rust compiler: our theorems are about source-level semantics as
  modeled, not about emitted machine code.
- Platform model: `usize` is at least 32 bits.
- **tacenta-core** is consumed as a dependency pinned by revision
  (`fb89b15`); this repository makes no verification claims about it. Its
  claims are its own, on a separate axiom baseline, and are not inherited
  here.

## Not claimed

- **No cryptographic security claims of any kind, from this repository.**
  tacenta-core provides the encryption; nothing *we* wrote or proved in this
  repository says anything about confidentiality, integrity, or
  authentication. The E2EE round-trip test shows the integration functions,
  not that it is secure. tacenta-core makes its own claims and they do not
  transfer here by being pinned.
- The specification itself is the definition of intent; proving code
  against it cannot catch a wrong intent.
- No claims about the server, transport, storage, timing, or
  side channels.
- **Nothing here covers `tacenta-core`.** The clean-room protocol library is
  pinned by this repository and built and tested by CI, but every claim on
  this page is about *this* repository's code and
  *this* repository's proofs. `tacenta-core` states its own claims and its own
  limits in its own `CLAIMS.md` and `LIMITATIONS.md`, on a separate axiom
  baseline.

  **The shipping provider is tacenta-core's `OpenParty`** —
  `DefaultProvider = open::OpenParty` in `crates/tacenta-core/src/crypto.rs`,
  and `DefaultClient = Client<DefaultProvider>` (decision record 0075).
