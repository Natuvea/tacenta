# 0024 — authorized identity rotation (key continuity)

## Decision

An address's bound identity key can be replaced, but only by the key that
currently controls it. Trust on first use alone (decision records 0018,
0019) would leave a device that rotates or re-keys its identity stuck with
the first key forever; this record adds the door.

Rotation splits along the same crypto / crypto-free seam as registration:

- **The directory gains a crypto-free `rotate`** (`Rotation::Rotated` /
  `Unregistered`). It replaces the identity and bundle bound to an address,
  and only for an address that is already bound. Like `register`, it does no
  cryptography — it trusts that the caller has verified authorization first,
  exactly as `register` trusts a verified proof of possession.
- **The caller (server) verifies two signatures** before calling `rotate`:
  1. *Proof of possession of the new key* — the new identity key signs the
     server challenge. You cannot rotate to a key you do not hold.
  2. *Authorization by the currently bound key* — the key the directory
     holds *now* signs a statement binding the new key (`challenge ++
     new_identity`). Only whoever controls the address today can hand it to
     a new key.

The load-bearing property is that authorization is checked against the
**current** binding, never a past one. Rotation forms a chain A → B → C in
which each step is blessed by its immediate predecessor, and a superseded
key can authorize nothing further. `tacenta-core`'s
`tests/identity_rotation.rs` demonstrates the chain, a stale key being
refused, and a third party — able to prove possession of its own key but
not to sign with the bound key — failing to take an address over.

## Considered

- **Let the directory verify the rotation.** Same reason `register` does not
  verify possession (decision record 0019): that is cryptography, and the
  directory stays crypto-free. The old-key signature check lives with the
  caller that owns the crypto.
- **A registration authority that signs rebindings.** Stronger, but it
  reintroduces the trusted third party the system avoids, and key continuity
  does not need it: the *old key itself* is the authority for its successor.
- **Allow rotation of an unbound address.** That is just registration; folding
  it in would blur the two. `rotate` returns `Unregistered` for an address
  with no binding, and callers use `register` for a first binding.
- **A revocation list / tombstones.** Superseded keys are handled implicitly
  (the directory holds only the current key, so an old key simply no longer
  matches). An explicit revocation record would matter for auditing or for
  peers caching an old key, but is out of scope here.

## Why

Trust on first use is the honest floor, but a floor with no door: a lost or
compromised device key would strand the address permanently. Key continuity
is the minimal, standard way to add rotation without a trusted third party —
the same shape as SSH host-key changes or a Signal safety-number change:
authority flows along a chain of keys, each vouched for by the last. Keeping
the binding replacement in the crypto-free directory and the two-signature
check with the server preserves the property that makes the directory simple
to trust — it stores and swaps bytes; the cryptography lives where the keys
do.

## Networked

The model, proven in-process (`tests/identity_rotation.rs`), is now also on
the wire: a `Rotate` request (`device`, new identity + bundle, and the two
signatures) on the directory protocol, verified by the same injected
`Possession` the server already uses for registration — possession of the
new key over the challenge, and the rotation authorization over `challenge
++ new_identity` by the currently bound key, checked and applied under one
lock so the binding cannot change between check and swap.
`tacenta-core`'s `tests/networked_rotation.rs` drives it over a real
socket: a rotation succeeds, a third party is refused, and rotating an
unregistered address is refused.

## What would reopen this

- **Lost-key recovery** is now addressed by a pre-provisioned recovery key
  (decision record 0025): a device that has lost its identity key re-keys by
  authorizing the rotation with the recovery key instead. Recover reuses
  this record's `rotate`; only the authorizing key differs.
- **Peer notification of a change.** A peer that cached the old key is not
  told the binding changed; safety-number-change UX (warn the peer, let them
  re-verify) is a client concern layered on top, not addressed in the
  directory.
