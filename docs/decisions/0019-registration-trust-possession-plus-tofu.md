# 0019 — registration trust: proof of possession plus trust on first use

## Decision

Admitting a directory registration takes two independent checks, split
along the same crypto / crypto-free seam as the rest of the system:

- **Proof of possession** (cryptographic). The registrant signs a
  server-chosen challenge with the identity private key it is submitting;
  the admitting server verifies that signature against the *submitted*
  identity key. This proves the registrant holds the key it claims. The
  check is cryptographic, so it lives with the caller admitting the
  registration (the server), not in the directory.
- **Trust on first use** (crypto-free, in the directory). The first
  registration of a device address binds it to an identity key. A later
  registration must present the *same* key: it may refresh the prekey
  bundle (`Refreshed`), but a different key is `Rejected` and changes
  nothing. `Directory::register` returns this outcome. The check is a
  byte comparison — no cryptography — so it stays in the crypto-free
  directory crate.

Each check turns away an attack the other cannot, and neither alone
suffices:

- Possession alone would let an attacker bind *their own* key to someone
  else's address — they can prove they hold their own key.
- Trust on first use alone would let an attacker submit *someone else's*
  identity key for a fresh address — there is no prior binding to compare
  against, and without possession nothing stops them claiming a key they
  do not hold.

Together they admit only a registrant who both holds the submitted key
and is not stepping on an existing binding.
`crates/tacenta-core/tests/registration_trust.rs` demonstrates both
attacks being turned away, one by each layer.

## Considered

- **A registration authority that vouches for identities.** A trusted
  issuer signs each identity-to-address binding. Stronger than trust on
  first use, but it introduces a trusted third party the rest of the
  system deliberately avoids, and it is not needed to close the two
  attacks above. Trust on first use is the weakest model that is honest;
  a stronger one can layer on later without changing this surface.
- **Let the directory do the possession check.** Would pull cryptography
  into the crypto-free directory crate, which is the one property that
  keeps it as simple to trust as the blind relay. Possession is the
  server's job precisely because it is cryptographic; the directory only
  compares bytes.
- **Permit identity rotation now** (replace the bound key). Doing it
  safely means the *new* registration is authorized by a signature from
  the *old* key — real key-rotation semantics. That is a distinct design
  with its own failure modes (lost-key recovery, revocation windows), so
  it is deliberately deferred rather than approximated.

## Why

A directory that took registration on faith would let any caller claim
any address with any key. The two-check model keeps every piece in the
layer that should own it — the directory stays a crypto-free store
that only enforces a byte-level binding invariant, and the cryptography
stays in the crypto layer and the admitting server. The result is an
honest, minimal trust model with a clear statement of what it does and
does not defend.

## What would reopen this

- **Authorized identity rotation** is now offered via key continuity
  (decision record 0024): a bound key is replaced only by a signature from
  the currently bound key. Lost-key recovery (no old key to sign with)
  remains a separate design.
- **The admitting server is demonstrated in a test, not yet a service.**
  The two-check admission lives in
  `tests/registration_trust.rs`; folding it into the networked directory
  service gives it a permanent home, with the server issuing
  real per-registration challenges.
- **Trust on first use trusts the first registrant.** If an attacker
  registers an address before its legitimate owner, they hold it. A
  stronger enrollment story (a registration authority, or binding
  addresses to an out-of-band credential) would reopen the model; trust
  on first use is the honest floor, not the ceiling.
