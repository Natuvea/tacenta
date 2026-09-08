# 0032 — the echo bot as a first-class reference agent

## Decision

The echo bot is its own crate, `tacenta-echo`, with a library
([`EchoBot`](../../crates/tacenta-echo/src/lib.rs)) and a runnable binary,
and it has its own tests. It connects as an ordinary [`Client`], echoes every
received message back to its sender, and — the load-bearing part — persists
its identity across restarts (decision record 0031), so a peer who has
messaged and verified the bot keeps the same bound key after the bot
restarts.

It is deliberately not a snippet inside `tacenta-demo` or a throwaway in a
test.

## Considered

- **A throwaway inside the demo or a test.** The path of least resistance: a
  loop in `tacenta-demo` or an ad-hoc fixture. Rejected on purpose — an echo
  peer is a standing thing (a real end-to-end check, the smallest agent
  identity, the natural first consumer of identity persistence), and burying
  it in a demo makes it an afterthought that no one can run on its own or
  build on.
- **Fold it into `tacenta-server`.** The server is cryptographically blind by
  design (it routes ciphertext it cannot read); an echo bot must *decrypt* and
  re-encrypt, so it is a client, not a server capability. Putting it in the
  server would breach that separation.
- **A generic bot framework, echo as the first bot.** Over-building. One
  concrete, well-made agent first; the reusable shape (connect, hold a durable
  identity, act on each message) can be lifted out when a second agent needs
  it.

## Why

An echo bot earns first-class status three times over: it is a live
end-to-end proof of the whole client stack (directory lookup, session
establishment, encrypt, relay, decrypt, all in one round trip that anyone can
run), it is the canonical agent identity, and it is the first real consumer
of client identity persistence. That last point is why it lands now, right
after 0031: the bot is the thing that most obviously *needs* a stable
identity, and building it proves the persistence surface against a real user
rather than only a test. `serve_once` (one receive-and-echo batch) is split
out from `serve` (forever) so the behaviour is drivable deterministically in
a test — the two tests assert it echoes, and that it keeps its identity and
still echoes across a restart.

## What would reopen this

- **A second agent.** When another agent identity appears, the reusable core
  (connect, durable identity, per-message handler) is extracted from
  `tacenta-echo` into a shared surface, and the echo bot becomes its first
  instance.
- **Reconnection and backlog drain land.** `serve` returns on a dropped
  connection today; once the client grows reconnect-and-resume, the bot's loop
  survives a disconnect instead of exiting.
