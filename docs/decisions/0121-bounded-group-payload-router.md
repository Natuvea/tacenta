# 0121 — bounded group payload router

## Decision

After pairwise authentication and relay classification as group traffic, the
client decodes the canonical inner group payload exactly once. Its tag chooses
either the application receiver or the roster-control transition. Both paths
commit the decrypting provider state in the same operation snapshot before
exposing an application disposition or a roster effect.

Malformed inner bytes retain their terminal provider effect as a durable
malformed disposition. A roster payload received from any peer other than the
pinned authority is recorded as the roster state's rejection; it does not
become an application message or change membership.

## Considered

- Let each caller decode and route the plaintext independently.
- Treat every group payload as an application context.
- Use one canonical tag router at the durable boundary.

## Why

Independent parsing could apply a control as application data or advance the
provider state without its group effect. One router keeps the parser choice,
provider transition, and group state transition attributable to the same
authenticated envelope.

## What would reopen this

Additional bounded control types can add tags and routes only with their own
durable transition and refusal behavior.
