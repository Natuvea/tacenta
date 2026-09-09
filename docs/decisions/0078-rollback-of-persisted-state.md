# 0078 — the directory witnesses state freshness, and an old state cannot resume a ratchet

## The problem

Persisted state is bytes in a file. Without a state MAC, a generation counter
and a monotonic anchor, an attacker who can write `state.bin` can replace it
with an earlier state and reopen everything forward secrecy is supposed to
close — old chain keys become live again, consumed one-time prekeys become
unconsumed, and the last-resort replay window reopens.

## The thing that makes this harder than it looks

**A MAC gives integrity, not freshness.** An attacker who can write the file can
write an *earlier, validly authenticated* file. Every byte checks out; the state
is genuine; it is simply old. Rollback is a freshness problem, and freshness
needs an anchor the attacker cannot rewind.

So the design reduces to one question: **where does the anchor live?** Inside
the blob is circular. Beside the blob, writable by the same attacker, is
worthless. Everything below follows from that.

## Anchors considered

**A. The directory holds the highest generation it has seen per device.**
Adopted. Each device record already binds an identity key, that binding is
already sticky — a later registration must present the same identity key — and
updates already carry a possession proof. A monotonically increasing
`state_generation` extends a record that exists, on a path that is already
authenticated, rather than inventing a mechanism.

It is also *metadata*, which the threat model already concedes the server sees.
The relay keeps no path to plaintext, so the blind-relay property of decision
0012 survives. **That argument is made here rather than assumed**, because
"the server learns one more number" is exactly the kind of change that is
harmless individually and corrosive if nobody writes it down.

And it works on every platform we ship to, which the strongest option does not.

**B. A wrapping key in platform secure storage.** Adopted as reinforcement, not
as the anchor. The blob's authenticator needs a key, and if that key lives
beside the blob then an attacker who rewrites one rewrites the other. Keychain,
Android Keystore or equivalent holds the wrap key; ordinary storage holds the
blob. Without this, A detects rollback at the server while the local file stays
freely forgeable.

**C. A hardware monotonic counter** (TPM NV index, StrongBox rollback
resistance). Rejected as primary, and it is the strongest anchor available.
iOS offers no general-purpose monotonic counter, and StrongBox rollback
resistance is device-dependent. Choosing C as primary would be choosing which
deployments get the protection. It remains the right answer for a deployment
that can guarantee the hardware, and this record should be revisited by anyone
who can.

**D. Detection without prevention.** Rejected as an end state, though A degrades
to it gracefully: a client that never contacts the server is never checked.

## Decisions

**1. The directory witnesses freshness.** A device record carries
`state_generation`. A client presents its generation on the authenticated paths
it already uses; a generation below the highest seen is a rollback and is
refused. The counter never decreases, and only the identity that owns the
binding can advance it, because the possession proof already governs that path.

**2. The generation advances on session-affecting events, not on every
message.** New session, prekey consumption, identity rotation. Not every
ratchet step.

This is a real trade and it is recorded as one. Per-message would mean a server
round trip *and* a full state write per message, and the state write measures
14,188 bytes per session — about 40% of send cost at one peer, and linear in
peers after that. Within a generation, the MAC covers integrity and the
generation covers freshness only at its own granularity. **What the witness
alone concedes**: an attacker who rolls back *within* a generation rewinds
ratchet progress without tripping it. The secure-storage counter below is what
closes that window, and the price of a protocol that stays usable is that the
closure rests on the counter's strength rather than on a server round trip
per message.

**3. An old state may be loaded. It may not resume an existing ratchet.**

This is the decision that matters most and the one least likely to be guessed
right. **Rollback and legitimate backup restore are indistinguishable from
outside**: a user restoring last week's backup performs precisely the attacker's
action, with precisely the same bytes. So "reject older states" breaks restore,
and "accept older states" is the vulnerability.

Neither. An older state loads, and every session in it is discarded rather than
resumed; the client establishes fresh sessions with each peer. A new session is
an ordinary event that the protocol handles every day, so the user gets working
software, and the attacker gets a client that has forgotten the chain keys they
wanted to replay.

The identity survives. The sessions do not. That is the whole of the policy.

**3a. At startup, before the witness has been reached, the client resumes
optimistically and discards sessions if the witness later reports a
regression.**

Decision 3 says what happens to a state known to be old. 3a says what happens
to a state whose age is not yet known, which is the state of every client
between process start and first contact with the directory — every launch, not
an edge case.

The alternative default is to assume stale until the witness confirms
freshness. It is safe and unusable: every offline start would discard every
session, so a client on a train would come back with nothing. A protection that
costs the user their conversations whenever the network is absent is one they
will find a way to turn off.

So the client resumes, and if the directory later reports a generation lower
than the highest it has seen, sessions are discarded at that point. **The window
this opens is stated rather than left to be discovered**: a rolled-back client
is live from launch until first contact. It is the same limit this design
already accepts overall, for the same reason — a client with no server contact
cannot receive messages, so the window buys an attacker very little — and it is
recorded here because "what happens before the check runs" is the question
that comes second.

## Consequences

- Restore is a **supported operation with a stated consequence**, not a footgun.
  The FFI's `exportState` documentation already warns that the blob is not a
  backup; under this decision that warning becomes precise rather than
  cautionary — restoring an older copy costs you your live sessions and nothing
  else.
- The server learns one number per device that it did not learn before. It is
  monotonic, it is not a plaintext, and it is bounded by information the
  directory already holds.
- A client that never reaches the server is never checked. Stated plainly: this
  design does not defeat an attacker who rolls a device back and keeps it
  offline. Such a device also cannot receive messages, which limits what the
  attack buys, and that limitation is the reason A is acceptable rather than an
  excuse for it. Decision 3a extends the same reasoning to the launch window,
  where the check has not run yet rather than never running.
- **Restore costs the user their undelivered messages, and nothing else.**
  Anything queued under a session that is discarded cannot be decrypted by the
  fresh session that replaces it. Peers see a new session rather than a changed
  identity, so there is no key-fingerprint event and nothing alarming on the other
  side. This is a documented consequence, not a redesign.

## Prerequisite

**Decision 0077 comes first.** The anchor attaches to the durable-write utility
that 0077 specifies, so that it protects every caller rather than one provider
on no shipping path.

## What would reopen this

- **A deployment that can guarantee hardware rollback resistance.** Option C is
  strictly stronger and this record is what should be revisited, not worked
  around.
- **The strength of the freshness anchor.** Decision 2 makes the generation
  coarse for performance, so the witness alone cannot see a same-generation
  rollback; the secure-storage counter (below) is what closes it, and it holds
  only as far as the store is rollback-resistant. The options for a finer
  anchor each cost something:
  - *Advance the generation per message (or per send).* Restores the freshness
    granularity at the witness, but the directory is the anchor, so catching
    every rollback there needs a witness round-trip per message on top of the
    14,188 bytes/session state write. Bounded variants (checkpoint every N
    messages, or only before an outbound send) narrow the window without
    closing it.
  - *A local rollback-resistant counter in secure storage* (not just a key — a
    monotonic counter), checked on restore without a server trip. Adopted; it
    is the closure that does not tax every message with a round trip, and it
    is why `SecureStore` holds a counter as well as a key.
  - *A hardware monotonic counter* (option C) — strictly strongest, device
    dependent.
  This bullet is the live one: it is a trade made against a measurement, and
  new evidence about the cost or the threat is reason to remake it.
- **Decision 3 being contested.** It is the least conventional choice here.

## Status

**Against a file-rewriter, rollback is defended for a deployment whose
`SecureStore` provides a rollback-resistant key and counter.** The layers, in
order of what each shuts:

- **Anchor A** (directory witness) detects a restore of an unmodified old state
  but does not defend a file-rewriter.
- **Anchor B** (the sealed export/restore path) closes the generation forgery: the
  generation is authenticated, so a file-rewriter cannot forge it.
- **The secure-storage rollback counter, committed per send.** A monotonic
  counter lives in `SecureStore`, where a file-rewriter cannot reach it. Every
  `send` and every ratchet-advancing `receive` commits it
  (`Client::commit_ratchet_advance`), and a sealed export binds its *current*
  value. On restore, a blob whose counter is below the store's high-water mark
  is caught and its sessions discarded — locally, without the server, so this
  holds offline too. Because the counter advances with the ratchet rather than
  only at export, a restore of any state older than the latest send is caught
  (`resilience.rs::a_send_after_the_latest_seal_is_caught_by_the_per_send_counter`,
  and `a_same_generation_older_seal_is_caught_by_the_counter`).

The Android sample store in `bindings/android/README.md` keeps the counter in
`EncryptedSharedPreferences`, app-private storage in the same class as the
state file, so it holds against a rewrite of the state file alone and not
against an attacker who can also restore the preferences file; the README says
so. Hardware rollback resistance (StrongBox) is the answer where the device has
it.

**What this rests on, stated plainly — it is conditional, not absolute.**

- **The `SecureStore` must actually be rollback-resistant.** A file-rewriter
  cannot touch Keychain / Keystore, so the counter defeats *it*. But a software
  counter in secure storage can be rolled back *with the store* — a device
  backup/restore, or a compromised secure store, rewinds the counter too. Only a
  hardware monotonic counter (option C) resists that. So this closes the
  rollback gap against the file-rewriter, not against an attacker who can roll
  the secure store itself back; that stronger attacker is the reason option C
  remains the strictly-stronger answer.
- **The mobile `SecureStore` implementation is unverified.** `bindings/swift`
  and `bindings/android` carry illustrative Keychain/Keystore code (with the
  counter), none device-tested. A mobile deployment inherits the closure only
  with a correct, hardened implementation.
- **Per-send cost.** The send path fails closed if the counter cannot be
  committed (no send without recording freshness); receive commits best-effort to
  avoid losing already-decrypted messages, so a secure-storage failure during
  receive leaves a narrow receive-side replay window. Both are stated in the
  code.
- **Anchor poisoning is a separate bound** (an identity-key holder poisons the
  directory anchor directly — its own fix, below).

The mechanism:

- The directory records the highest generation seen per device
  (`tacenta-directory`, `Directory::witness`), in its own map so a registration
  refresh does not reset it, resetting on rotation, and persists it in
  the snapshot (v3).
- The transport carries it: `DirRequest::Witness` proves possession against the
  bound identity; the directory answers `Fresh` or `RolledBack`.
- The client advances a `state_generation` on session-affecting events (decision
  2). On `RolledBack`, `Client::checkpoint` discards its sessions and keeps its
  identity (decisions 3/3a) through `CryptoProvider::clear_sessions`.
- **Anchor B: the sealed path (`state_generation` authenticated).**
  `Client::export_state_sealed` seals a v3 body under a 32-byte key from a
  `SecureStore` (the seam), binding the generation *inside*
  `tacenta_core::persist::seal` rather than appending it in plaintext. The blob
  is tagged v5. `connect_with_state_sealed` / `sign_in_with_state_sealed`
  `unseal` it — **a state a file-rewriter forged has no matching authenticator
  and is refused, not resumed** — and then checkpoint automatically, because a
  generation that survived the seal is one the witness can trust. This is where
  `persist.rs`'s `seal`/`unseal` have their call site.
- **The secure-storage rollback counter (the finer anchor).** `SecureStore`
  holds a monotonic counter as well as the key. The client commits the counter on
  **every send and every ratchet-advancing receive** (not on export);
  `export_state_sealed` binds the *current* value into the sealed body. The sealed
  restore reads the store's high-water mark and, if the blob's counter is lower,
  discards sessions
  (`Client::discard_sessions`, the same action a directory `RolledBack` triggers).
  Because the counter lives in secure storage — unreachable to a file-rewriter —
  and only increases, this catches a same-generation rollback the coarse
  generation cannot: restoring an *older saved state*.
- **The unsealed path (`export_state` / `connect_with_state`, v4) is unchanged
  and opt-in.** Its generation is a plaintext `u64` tail a file-rewriter
  forges, so it makes no rollback claim and does not auto-checkpoint. It
  remains for deployments with no secure storage, and as the detection-only
  tool `checkpoint` still exposes.
- Tests: `resilience.rs::a_forged_sealed_generation_is_refused` (a forged
  generation refused by the seal), `a_rolled_back_sealed_state_is_caught_on_restore`
  (a genuine old sealed state caught by the witness on restore, sessions
  discarded), `a_current_sealed_state_restores_fresh_and_keeps_its_sessions`, and
  the crate-level `sealed_and_unsealed_formats_do_not_cross_parse` /
  `a_forged_generation_in_a_sealed_blob_is_refused`. The `#[ignore]`d
  `a_forged_generation_defeats_rollback_detection` stays as documentation of the
  *unsealed* path's by-design limit.

**What B closes, precisely.** With the generation authenticated:

- **The forged-generation gap is closed on the sealed path.** A file-rewriter who sets the generation
  to `u64::MAX` cannot produce a matching authenticator (the key is not in the
  file), so `unseal` refuses and the restore fails closed. The forgery A alone
  cannot see is caught.
- **A genuine older sealed state from a *lower* generation is caught** by the
  witness — a legitimate backup restore (decision 3's target) or an attacker
  replaying an untouched old sealed file *from before a session-affecting event*
  presents a low generation, so checkpoint reports `RolledBack` and the sessions
  are discarded (`a_rolled_back_sealed_state_is_caught_on_restore`).
- **A same-generation older *saved* state is caught by the counter.** Two seals at
  the same generation carry different counters; restoring the older one presents a
  counter below the store's high-water mark and its sessions are discarded
  (`a_same_generation_older_seal_is_caught_by_the_counter`). This shuts the
  practical rollback attack — keep an old state file, restore it later — that the
  generation alone cannot.

**What remains open, stated plainly.**

- **The closure rests on the strength of the secure-storage counter.** `send`
  and ratchet-advancing `receive` commit the counter on every call, so a restore
  of any state older than the latest send presents a lower counter and is caught
  (`a_send_after_the_latest_seal_is_caught_by_the_per_send_counter`). A software
  counter falls to a rollback of the store itself; only a hardware counter
  (option C) resists that.
- **The FFI seam is wired; a hardened platform key source is the remaining gap.**
  `tacenta-ffi` exposes the sealed pair (`exportStateSealed`,
  `connectWithStateSealed`, `signInWithStateSealed`) and a `SecureStore` callback
  interface the foreign side implements — verified by the Swift binding
  typecheck and Kotlin generation. What does **not** ship is a first-party,
  device-verified Keychain / Keystore implementation of that callback:
  `bindings/swift` and `bindings/android` carry *illustrative* implementations an
  app must inspect and harden, and none has been exercised on a real device. So
  mobile *can* close the rollback gap today by implementing the callback correctly, but the
  project makes no claim that a hardened implementation is provided or tested.
  The Rust mechanism itself is tested through a mock key (no Keychain exists in
  CI). A desktop OS-keyring implementation is a separate follow-up, deliberately
  **not** taken here: it needs a new dependency, which gets the same
  supply-chain / cargo-audit scrutiny any dependency does in this repo.
- **Anchor poisoning is not closed by B.** Sealing the *blob* stops a file-rewriter forging
  the generation; it does nothing about an attacker who holds the identity key
  and sends `Witness(u64::MAX)` to the directory *directly*, poisoning the anchor
  so later legitimate connections report `RolledBack` — a DoS. That is a
  directory-endpoint bound, not a blob-authentication one, and it needs its own
  fix (bounding or binding the witnessed generation). It stays bounded for now:
  it needs the identity key (a deeper compromise than file rewrite), and rotation
  resets the anchor, which is the recovery path.
- **A device rolled back and kept offline is never checked** (it also cannot
  receive — the limit this whole design already accepts). And an attacker who
  defeats platform secure storage itself (a jailbroken/rooted device) recovers
  the key and can forge again — that is the trust anchor B rests on, named in the
  "Anchors considered" B/C discussion, not a regression.

The witness rule is also **tested, not yet Lean-refined** — it lives in the glue
crate so it does not perturb the refined `tacenta-directory-core`.

The `persist.rs` authenticator is HMAC-SHA256 under
`tacenta:persisted-state:v1\xff`, following the scheme
`tacenta-core/LABELS.md` sets for new labels. Its payload is authenticated and
**not** encrypted; at-rest confidentiality is a boundary
`tacenta-spec/protocol/key-deletion.md` states as the caller's job, to be taken
as its own decision.

**On the whole-frame question.** A's witness travels on the authenticated
directory path. The generation rides *inside* the already-possession-proven
`Witness` request, so if the possession proof is later extended to cover the
whole frame rather than the challenge, the generation is inside whatever ends
up covered — building it now is consistent with that outcome rather than
pre-empting it.
