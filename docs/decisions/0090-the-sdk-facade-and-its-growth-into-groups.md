# 0090 — the SDK facade and its growth into groups

## What this is

This record fixes what the SDK is: one facade in Rust that every language head
is generated from, and how each published package is checked to match it. It
builds on 0028 (the facade), 0029 (UniFFI first), and 0052 (the Swift package).

## Decision

One facade, generated heads. `tacenta-client` is the SDK. Every language package
is a thin head over it: UniFFI for Swift and Kotlin, wasm-bindgen for TypeScript,
the crate itself for Rust. No head carries logic of its own beyond idiom (async
style, error type, byte type); a behaviour that exists in one head exists in all.

The surface itself is not restated here, so it cannot drift out of date. The
authoritative, per-head surface is generated from `sdk/surface.json` and rendered
in `sdk/SURFACE.md`, which is the single source of truth: the tenant handle, the
signed-in client, inbound messages, and the error kinds, each with the symbol
every head exposes. A test in each head checks itself against the manifest, so
the grid cannot drift from the code without a test failing.

A conformance suite is the evidence. Each published package is to be driven
through the same suite against a deployed server, and the transcript is the
evidence that a head does what the Rust does.
