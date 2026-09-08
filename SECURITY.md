# Security policy

## Reporting a vulnerability

Email **security@natuvea.com**. Please do not open a public issue for a
security report.

If you would like to encrypt the report, ask for a key in a first message with
no details in it.

**What to include.** The affected component and revision, what an attacker
gains, and the smallest thing that demonstrates it. A failing test or a byte
string is worth more than a paragraph. If you are unsure whether something is a
vulnerability, report it — deciding that is our job, not yours.

**What to expect.** We will acknowledge within three working days, tell you
whether we consider it a vulnerability within ten, and agree a disclosure
timeline with you rather than imposing one. If we disagree with your assessment
we will say so and say why. You will be credited unless you ask not to be.

We will not take legal action against anyone acting in good faith under this
policy.

## What is in scope

This repository is **pre-release**. The crates are not published to a registry
(`publish = false`), there is no supported-version policy yet, and it has not
been independently audited. Read that as the current state, not as a
disclaimer against reports.

In scope:

- The protocol implementation and its wire formats.
- Session, identity, prekey, and persistence handling.
- The relay, server, and client crates.
- Anything where our documented claims overstate what the code does. A claim
  that is wrong is a finding here, and we would rather hear it from you than
  from a customer.

Out of scope, because they do not exist rather than because we do not care:

- **Group messaging (sender keys)** and **Sesame / multi-device session
  management**. Not implemented.
- **Message-layer interoperability with other implementations** is out of
  scope.

## Known limitations

We publish what we already know rather than letting a reporter spend time
rediscovering it. At the time of writing:

- XEdDSA is a custom implementation with no published known-answer vectors.
- The decoder's 32-bit behaviour is checked by reading and by 64-bit tests;
  there is no 32-bit runtime regression test.

Reporting a sharper version of any of these — in particular a concrete exploit
path — is genuinely useful and welcome.

## What we do not consider vulnerabilities

- Findings against the trusted boundary we document rather than hide: the Lean
  kernel, the Charon/Aeneas translation, the Rust compiler, and the primitive
  crates we depend on. Report those upstream; tell us too, and we will act.
- Anything requiring an attacker who already has the victim's device and its
  keys at rest. See `docs/threat-model.md` for where that line sits.
- Volumetric denial of service against a deployment you do not own.

## Cryptography, specifically

The strongest thing you can do for this project is disagree with a claim in
`docs/claims.md`, or with the scope stated in tacenta-core's `CLAIMS.md` and
`LIMITATIONS.md`. Those documents exist to be falsifiable. "Some leaf
properties are machine-checked; the protocol implementation is not proven" is
our own summary, and if any part of the repository reads as claiming more, that
is a defect worth reporting.
