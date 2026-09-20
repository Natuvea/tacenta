# 0118 — bounded group control envelope

## Decision

Encrypted `group` relay payloads carry a canonical inner envelope with exactly
two first-profile variants: application context and roster control. The envelope
uses a fixed domain, one explicit type byte, and a length-prefixed canonical
value. Decoding applies the corresponding bounded application-context or roster
codec and rejects unknown type, wrong domain, length mismatch, or trailing
bytes.

Roster controls remain pairwise-authenticated through the existing provider;
the envelope itself does not grant authority. The client verifies the
authenticated sender against the currently pinned authority before it asks the
roster view to accept a control transition.

## Considered

- Guess control/application type from its contents.
- Send roster bytes as a direct message outside the group envelope.
- Use one explicit bounded inner envelope under the `group` class.

## Why

Membership progression needs a live authenticated control path without letting
raw roster bytes be mistaken for application content. The type byte gives the
receiver a parser choice before it evaluates either state machine.

## What would reopen this

Invitation history, close receipts, or a production signed-control protocol
need successor types and a versioned capability rule.
