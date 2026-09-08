# 0023 — TLS for the transport

## Decision

Both transports can run over TLS. The relay and directory protocols are
unchanged — TLS wraps the byte stream they already speak, not the protocol.

- **The transport is generic over its stream.** `serve_connection` /
  `serve_authenticated` / `serve_dir_connection` take any
  `AsyncRead + AsyncWrite`, and the client connections split and box their
  halves, so `Connection` / `DirConnection` are transport-agnostic. A TLS
  stream is just another such stream.
- **TLS is a wrapping layer.** `serve_tls` / `serve_directory_tls` wrap each
  accepted TCP connection in a `tokio_rustls` acceptor before the framed
  protocol runs; `connect_as_tls` / `connect_tls` wrap the client side.
  `ServerTls` (cert chain + key) and `ClientTls` (which server cert to
  trust) hold the rustls config; the transport stays otherwise unchanged.
- **rustls with the `ring` provider.** Pure Rust, no OpenSSL. `ring` rather
  than the default `aws-lc-rs` to keep the build light (no cmake / C
  toolchain); the provider is installed as the process default once, lazily.
- **The server exposes it as config.** `Config.tls` (PEM cert + key paths,
  `TACENTA_TLS_CERT` / `TACENTA_TLS_KEY`); set both to serve TLS on both
  ports, otherwise plaintext TCP.

## What TLS does and does not add

TLS protects the **transport**: it encrypts the metadata a network observer
would otherwise see (who connects, the challenge/response handshake, the
sizes and timing of the opaque ciphertext) and authenticates the server to
the client, so a man in the middle cannot impersonate the server or tamper
with the framing. It is **defence in depth**, not the basis of the system's
security: message *content* is already end-to-end encrypted by
`tacenta-core` underneath, so the server — TLS or not — never sees
plaintext. The claim is exactly "the transport is encrypted and the server
authenticated," never "TLS secures the messages."

## Considered

- **A protocol-level encryption instead of TLS.** Rolling our own would be
  the exact anti-pattern the project avoids: don't invent crypto. TLS is the
  standard transport security; rustls is a widely used implementation.
- **`aws-lc-rs` (rustls default) vs `ring`.** aws-lc-rs is FIPS-capable but
  pulls a C build (cmake). `ring` is lighter and sufficient here; the choice
  is isolated to a Cargo feature and one provider install, so it can change
  without touching the transport.
- **Client certificates (mutual TLS).** The client already authenticates at
  the application layer (the signed challenge, decision records 0015/0019),
  so mTLS would duplicate identity at the transport layer. Left out; the
  server is authenticated to the client, not vice versa, at the TLS layer.
- **WebSocket framing.** A deployability concern (proxies, browsers), not a
  security one, and the same frames would ride it. Deferred; TLS is the
  security piece the plaintext gap actually needed.

## What would reopen this

- **Certificate management.** The server loads a PEM cert + key from disk;
  there is no rotation, no ACME/Let's Encrypt integration, and the pinning
  helper (`ClientTls::trusting`) trusts one cert. A deployment wants managed
  certificates and standard web-PKI trust as an option.
- **No WebSocket transport.** Browser and proxy-friendly framing is still
  future work; the generic-stream refactor that enabled TLS also makes a
  WebSocket adapter a wrapping layer rather than a rewrite.
- **mTLS / channel binding.** If the application-layer auth were ever to
  lean on the transport (e.g. binding the identity proof to the TLS channel),
  that is a distinct design.
