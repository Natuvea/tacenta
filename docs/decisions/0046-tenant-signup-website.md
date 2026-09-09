# 0046 — tenant signup website + HTTP control-plane gateway

## Decision

Tacenta gains a public website where a tenant signs up and receives an API key,
plus a quickstart guide, with docs to follow. Two pieces, split by
the fact that the account service speaks a **TCP framed binary protocol**, not
HTTP — a browser cannot talk to it directly:

1. **`tacenta-gateway`** — a new crate in *this* repo. A small HTTP/JSON service
   in front of the account store, so browsers (and any HTTP client) can perform
   control-plane signup. It reuses `AccountStore`, so it inherits the same
   argon2id hashing, coarse errors, and (for later endpoints) session handling,
   and it stays under the same verification discipline as the rest of the
   protocol code.

2. **`tacenta-web`** — a new **sibling repo**. A content-first static site
   (landing, quickstart, later docs) with a small script for the signup form.
   A separate repo because it deploys on its own cadence, uses a web stack
   rather than Rust, and grows a docs surface that should not churn the
   protocol monorepo. It is a pure frontend: it calls the gateway's HTTP API
   and holds no secrets.

```
Browser (tacenta-web, sibling repo)
   │  HTTPS + JSON
   ▼
tacenta-gateway (this repo)  ──TCP framed / TLS──►  account service
  POST /v1/tenants                                  AccountStore::sign_up_tenant
```

### The gateway API (v1)

- `POST /v1/tenants` — body `{ "username", "email", "password" }`; on success
  `201 { "tenant_id", "api_key" }`. The API key is returned **once** (the store
  keeps only its hash); the website must make the user copy it. `SignupError`
  maps to `409` (username/email taken) or `422` (invalid username/email, weak
  password) with a coarse machine reason, mirroring the wire protocol's
  `SignupReason`.
- v1 is signup-only. Tenant sign-in, viewing/rotating the key, and user
  management are additive later work (they need sessions and cookies).

### Security posture for the gateway

- **Per-IP rate limiting** on `POST /v1/tenants`. This is where the source
  address lives, so it is the natural home for the **signup-throttling** gap the
  threat model records (0042 rate-limited sign-in but left signup open). A
  sliding-window limiter like `ratelimit`, keyed by client IP (honouring a
  trusted proxy header only when configured).
- **CORS** scoped to the website origin(s); no wildcard.
- **TLS only** — the body carries a plaintext password, exactly as the account
  TCP protocol requires TLS today.
- **Email is stored but unverified.** Tenant email verification (a confirmation
  link) is later work; v1 accepts the email as-is, as the account store
  already does.
- No cookies/sessions in v1 (signup returns the key and is done), so no CSRF
  surface yet.

### The website (v1 pages)

- **Landing** — one screen: what Tacenta is, and a "Get an API key" CTA.
- **Sign up** — the form; on success, the API key shown once behind an explicit
  "copy this now — it will not be shown again" step.
- **Quickstart** — get key → install the SDK → sign up a user → open a room →
  send a message, with copy-pasteable samples. Slice-gated to shipped surface.

Voice + brand follow the same restrained, literary register as the rest of the
docs (no exclamation marks, sentence-case headlines, numbers that earn their
place).

## Verification (planned)

The gateway gets the same treatment as the rest of the repo: `cargo test` (HTTP
handler behaviour — success, each `SignupError` mapping, rate-limit trip, CORS
headers), clippy and fmt, in CI. A cold
end-to-end check: bring up the account service + gateway, `POST /v1/tenants`,
and confirm the returned key authenticates a subsequent user signup.

## Considered

- **The website's own backend bridges the TCP protocol** (a server-side
  script speaking the framed binary protocol). Rejected: it reimplements the binary
  client in JS and couples the two repos; the account store's logic (hashing,
  error mapping) would either be duplicated or reached only through the raw
  socket. An HTTP gateway in Rust reuses `AccountStore` directly and keeps the
  binary protocol in one language.
- **Website in this repo.** Rejected: different stack, different deploy cadence,
  and a docs surface that should not churn the protocol monorepo. The
  gateway, being server-side Rust that needs `AccountStore`, does belong here.
- **Add HTTP directly to `tacenta-server`.** Reasonable, but a separate gateway
  crate keeps the account TCP service and the browser-facing HTTP service
  independently deployable and separately rate-limited, and keeps the server
  binary focused.

## What would reopen this

- **Tenant sign-in** turns the gateway from stateless signup into a
  session-bearing API — cookies, CSRF, and the sign-in/revocation endpoints.
- **Email verification** for tenants adds a confirmation-link flow and a
  `verified` state on the tenant.
- **A managed cloud** (multi-region, billing) would grow the gateway well beyond
  signup; at that point it is its own control-plane service, not a thin bridge.
- **The account wire protocol gaining an HTTP-native transport** would remove the
  need for a bridge — unlikely, since the binary protocol is deliberate.
