# 0009 — stream framing is length-self-describing, no separators

## Decision

A transport stream is the bare concatenation of encoded envelopes. No
frame separators, no outer length prefix, no count header. `decodeOne`
parses one envelope and returns the unconsumed remainder; `decodeStream`
iterates it until the buffer is empty. Specified in
`spec/Tacenta/Stream.lean` with the round-trip theorem
`decodeStream_encodeStream`; mirrored in `tacenta-wire`
(`encode_stream` / `decode_stream`).

## Considered

- **Length-prefix each frame** (`u32 len ++ envelope`). Redundant: the
  envelope header already carries its payload length, so its total size
  is computable — a second length is a second source of truth that can
  disagree with the first.
- **A count header** (`u32 n ++ n envelopes`). Forces the sender to know
  the batch size before serializing, and adds a cross-field invariant
  (count matches the number of frames) to validate and prove.

## Why

The envelope is already self-delimiting, so concatenation is the
minimal correct framing — nothing to keep consistent, nothing extra to
prove. The round-trip theorem is correspondingly clean: it rests only
on `decodeOne_encode` (one encoded envelope plus any suffix parses back
to that envelope and the suffix), inducted over the list. Fewer wire
invariants is fewer things an implementation or an attacker can put out
of agreement.

Note this is a *framing* decision, not a *transport* one: it assumes the
stream is delivered intact and in order (e.g. over TCP/TLS). Partial
reads and reassembly are the transport layer's job, above this.

## What would reopen this

- A transport that hands us frames out of order or with gaps would need
  per-frame sequencing — but that is a transport envelope around this,
  not a change to this format.
- A need to skip a corrupt frame and resync (rather than reject the
  whole stream) would want frame boundaries the parser can hunt for; a
  deliberate robustness/complexity trade with its own record.
