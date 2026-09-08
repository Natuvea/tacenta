# 0025 — lost-key recovery via a pre-provisioned recovery key

## Decision

Key-continuity rotation (decision record 0024) requires the *old* identity
key to authorize its successor — so a device that has lost its identity key
entirely is stranded. Recovery closes that: a device provisions a
**recovery key** in advance, whose private half it keeps offline (written
down, in a safe, derived from a passphrase — not on the device). If the
identity key is later lost, the device re-keys by authorizing the rotation
with the recovery key instead of the lost one.

The recovery key is stored separately from the entry (`Directory.recovery`,
a per-device `Vec<u8>`), because it is orthogonal — set and used rarely,
not every device has one — so `register` / `rotate` need not carry it. Two
operations, each split along the crypto / crypto-free seam like the rest:

- **`set_recovery(device, key)`** — attach (or replace) the recovery key,
  authorized by the *currently bound identity key* (the same authority that
  authorizes a rotation). The directory stores the bytes; the admitting
  server verifies the identity-key signature first. Only for an address
  that is already bound.
- **Recover** — rotate the identity, authorized by the *recovery key*. The
  server verifies possession of the new key and a recovery-key signature
  over `challenge ++ new_identity`, then calls the existing
  `Directory::rotate`. No new directory method: recovery is rotation with a
  different authorizing key, so it reuses the crypto-free `rotate`.

Both operations are on the directory wire protocol (`SetRecovery`,
`Recover`) and verified by the same injected `Possession`.
`tacenta-core`'s `tests/recovery.rs` drives the whole flow over a socket: a
device provisions a recovery key, re-keys with it after "losing" the
identity key, and a third party — holding neither the current identity key
nor the recovery key — can do neither; recovering an address with no
recovery key set is refused.

## Considered

- **Store the recovery key in the entry** (extend `Entry`). Would ripple
  through `register` / `rotate` / the snapshot for a field most entries do
  not use. A separate map keeps the common paths unchanged and the recovery
  feature self-contained.
- **A dedicated `recover` directory method.** Recovery replaces the binding
  exactly as rotation does; only the authorizing key differs, and that
  check is the server's (cryptographic). So recover reuses `rotate` — the
  directory gains only `set_recovery` / `recovery_key`, no new mutation of
  the binding.
- **A social-recovery / trusted-contact scheme.** Stronger against a lost
  *recovery* key too, but it introduces third parties and a quorum protocol
  — a much larger design. A single pre-provisioned recovery key is the
  minimal thing that survives device loss without a trusted party.

## Why

A messenger whose only re-key path needs the key you lost is not usable
after a lost or wiped device. A pre-provisioned recovery key is the
standard, trusted-party-free way to survive that: authority to re-key flows
from a key set aside in advance, exactly as continuity flows from the
current key. Keeping the recovery key in a separate crypto-free store and
the two signature checks with the server preserves the property that makes
the directory simple to trust, and recover reusing `rotate` keeps the
binding-mutation surface a single, already-tested method.

## What would reopen this

- **Losing the recovery key too.** If both the identity key and the
  recovery key are gone, the address cannot be re-keyed — that is the
  irreducible floor without a trusted party or a social-recovery quorum,
  both out of scope here.
- **Recovery-key rotation and revocation.** Replacing a compromised
  recovery key is authorized by the current identity key (via
  `set_recovery` again), but there is no revocation record; a peer caching
  an old recovery key is not notified.
- **Peer notification of a binding change.** Recovery changes the bound
  identity, so a peer who verified the old one should be warned to
  re-verify (safety-number-change UX) — a client concern layered on top,
  not addressed in the directory.
