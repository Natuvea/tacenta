# 0071 — the identity-change and replay policy

> Amended 2026-09-30: the last-resort replay record described under "The bound
> this policy states rather than hides" is not what the pinned tacenta-core
> does. See "Amended 2026-09-30" at the end; the text between is left as written.

## Why this exists

The enforcement exists in code, in the tacenta-core repository: its
`tacenta-core/AUTHENTICATION-BOUNDARY.md` registry and
`tooling/check_authentication_boundary.py` fail that build on a receive path
that commits state before authenticating. This record is the statement of
what that enforcement guarantees, so the registry and the tests have
something to be checked against.

It describes what the code does, not what would be desirable, and it separates
three things: what is **enforced in code**, what is **documented but
unenforced**, and what is **absent**.

## Replay of an initial (prekey) message

**A repeated initial message is expected, not an attack.** An initiator repeats
its initial message on every message until the peer answers, which the Double
Ratchet specification recommends so a lost or reordered first message does not
strand the conversation. Any policy that treated repetition as hostile would
break the recommended behaviour.

So the rules are:

1. **On an established session, an initial message is accepted only if it is the
   one that established that session.** The responder stores the initiator
   ephemeral it established from and compares; anything else is
   `NotARepeatedInitial`. This is a *session-routing* check, not an anti-replay
   check, and calling it one would be an overclaim: it decides which session a
   message belongs to, and then the ratchet decides whether the message is fresh.
2. **A prekey named by an initial message is read, never consumed, until the
   ciphertext authenticates.** Deletion happens once, at the end, after the tag
   verifies, so holding a published bundle is not the ability to consume its
   one-time prekeys.
3. **A one-time prekey is consumed exactly once.** A later initial message
   naming a consumed identifier is refused with `UnknownPrekeyId`.

### The bound this policy states rather than hides

**Rule 3 protects while one-time prekeys last.** `OpenParty` publishes with
thirty-two; `PrekeyStore::replenish` adds more, continuing the identifier
sequence from `next_id`, and `one_time_remaining` is what a caller polls to
decide when. Between exhaustion and replenishment a bundle carries no one-time
curve prekey and falls back to the reusable last-resort KEM key.

On that path `establish_responder` performs no one-time lookup and no
consumption. The rule for it is separate: **a replayed last-resort handshake is
refused, within a bound.** The store keeps a fingerprint of each last-resort
handshake it has accepted, over exactly the fields that determine the shared
secret, and refuses a repeat. The record holds 1024 entries, oldest evicted
first; past that many *distinct* last-resort handshakes, a replay of the oldest
is accepted again. A replay the record does not catch derives the same shared
secret and opens a duplicate session: the attacker learns nothing and cannot
decrypt anything they could not already, and the number of sessions one
captured message can open is bounded by the record rather than by the
protocol. `tacenta-spec/protocol/key-deletion.md` states both halves.

## Replay of an ordinary ratchet message

**A replayed ratchet message is refused, and it is refused by the authenticator
rather than by a replay rule.** The message key was spent and removed when it was
first used; a replay finds nothing stored, derives the wrong key at the current
counter, and fails the AEAD tag. Every state change the attempt made is
discarded, because the whole receive runs against a candidate that is adopted
only on success.

Stated plainly, because the mechanism matters to anyone reading for a replay
check and not finding one:

- **Skipped message keys are one-use.** Taking one removes it.
- **The store is bounded twice** — per chain (`MAX_SKIP`) and in total
  (`MAX_SKIPPED_STORE`) — and in the classical ratchet also **expired by age**
  (`MAX_SKIPPED_AGE`, counted in received messages, since nothing here can read
  a clock). The sparse post-quantum ratchet bounds but does not age.
- **There is no error that says "replay."** The observable outcome is an
  authentication failure. This is deliberate: a distinct replay error would tell
  an attacker that a particular ciphertext was previously delivered, which is
  more than a refusal should reveal.

## Identity change

**Identity is bound at establishment and never revisited within a session.** The
associated data fixes both identity keys when the session is created, so a peer
whose identity key changes mid-conversation does not produce a session that
silently continues under a new key — it produces messages that fail to
authenticate. That is the enforcement, and it is a consequence of the binding
rather than a check.

**Change is handled at the directory, not the session.** Registration is trust on
first use: a new name binds, a matching key refreshes, and a mismatched key is
rejected while the existing binding stands. Rotation is permitted but must be
authorized by the **currently bound** key and demonstrate possession of the new
one — never by a past binding (decisions 0019, 0024, 0041).

**`PublicState::peer_identity` reports; it does not decide.** Its doc comment
says it is "used to detect a changed peer identity", and nothing in the library
consumes it. Whether a changed key is "the same contact with a new device" or an
impostor is an application judgement, and the library declines to make it. The
comment names the field's *purpose for a caller*, not a behaviour of the
library.

## The three-column summary

| | |
|---|---|
| **Enforced in code** | authenticate-then-delete ordering; candidate-and-commit on every receive path, checked by the boundary registry; `NotARepeatedInitial` for a different initial on an established session; `UnknownPrekeyId` for a consumed one-time prekey; a bounded last-resort replay record; replenishment that continues the identifier sequence; one-use skipped keys with per-chain and total bounds; age expiry in the classical ratchet; directory trust-on-first-use; rotation authorized only by the current binding |
| **Documented, not enforced** | prekey-identifier uniqueness across a store (a `Vec` does not enforce it; `replenish` continuing from `next_id` is what makes a collision impossible, and nothing checks the invariant afterwards); `PublicState::peer_identity`'s stated detection purpose |
| **Absent** | any cross-session replay tracking; any mid-session identity-change detection or warning; age expiry in the sparse post-quantum ratchet |

## What this policy does not claim

It does not claim replay is impossible. It claims replay of a *ratchet* message
fails authentication, replay of an *initial* message naming a one-time prekey
is refused, and replay of a last-resort handshake is refused within the bound
of the record.

It does not claim the library detects identity change. It claims a changed
identity cannot continue an existing session undetected, and that deciding what a
change *means* is the application's.

It does not extend to group messaging, which does not exist; multi-device
fan-out is covered by decision 0018.

## What would reopen this

- **The last-resort record's bound.** 1024 entries is a policy number; a
  deployment whose last-resort path is not rare needs the bound revisited or
  replenishment made more aggressive. This policy should be edited, not
  appended to, when that changes.
- **Safety-number-change UX.** The moment the product warns a user that a
  peer's key changed, "the library declines to judge" stops being the whole
  story and the division of responsibility needs restating.
- **Age expiry reaching the sparse ratchet.** The asymmetry with the classical
  ratchet is currently unexplained rather than justified.

## Amended 2026-09-30

This record was written on 2026-09-09. Two days later tacenta-core `e1537e6`
(the core of v1.12.0, 2026-09-11) replaced the last-resort replay window with a
record that fails closed, and the pin has moved on since. The sections above are
left as they were written; where they disagree with this section, this section
is what the pinned tacenta-core does. This record asked to be edited, not
appended to, when the bound changed. The project's later practice is a dated
amendment, as in 0092 and 0116, and this note follows that practice so that the
earlier reasoning stays readable.

**What changed.**

- **Nothing is evicted.** The record no longer holds "1024 entries, oldest
  evicted first", and a replay of the oldest handshake is no longer accepted
  again. Each last-resort key has a budget of 1,024 distinct accepted
  handshakes over its lifetime (`MAX_LAST_RESORT_SEEN`, counted per key, so the
  current key and, after a rotation, the retired one each have their own). A
  repeat of an accepted handshake is refused with `ReplayedLastResort` whether
  or not any budget is left. A handshake that is new and names a key whose
  budget is spent is refused with `LastResortRecordFull`, before anything is
  decrypted or changed. Entries leave the record only when a rotation wipes the
  key they belong to.
- **What identifies a handshake.** The fingerprint is derived from the shared
  secret the handshake derives, and not from the bytes of the initiator's
  ephemeral key, so two spellings of one ephemeral key are one entry
  (GHSA-v95x-f6p3-4qxg; the pinned revision contains that fix). A record saved
  by an older format cannot be compared with these fingerprints, so a store
  that holds one loads with its live last-resort keys closed until they are
  rotated (`CHANGELOG.md`, Unreleased).
- **The sentence about sessions is withdrawn.** "The number of sessions one
  captured message can open is bounded by the record rather than by the
  protocol" described the eviction design. A captured last-resort message opens
  no second session while the record refuses it.

**What it costs, which the original did not have.** Failing closed trades a
replay path for an availability one. Anyone who holds the published bundle can
complete last-resort handshakes under fresh identities cheaply, so anyone can
spend a key's budget; after that, legitimate first contacts that arrive by the
last-resort path are refused until the key is rotated, and a determined
attacker spends the fresh budget as well (tacenta-core, LIM-19). The relief
that holds is to keep one-time prekeys stocked, which is what makes the path
rare (`replenish`, and the directory's dispensing in 0074), and to limit how
fast bundles are fetched. This repository keeps one-time prekeys stocked; it
does not limit how fast bundles are fetched, because the directory's throttle
covers new handle registrations and not lookups. It also never calls
`rotate_kem`, so nothing in the SDK resets a spent budget.
`docs/threat-model.md` states the same.

**Read the rest of this record accordingly.** In "The three-column summary" the
row "a bounded last-resort replay record" means a record that fails closed. In
"What would reopen this", the last-resort record's bound is now a budget and
not a window: a deployment whose last-resort path is not rare meets refusals,
not accepted replays, and needs replenishment made more aggressive or a
rotation policy, which this repository does not have. The record still does not
claim that replay is impossible: it depends on the persisted record being
written in order and not rolled back (0078).
