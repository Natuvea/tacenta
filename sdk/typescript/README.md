# @tacenta/sdk

End-to-end encrypted messaging for your app, in browsers and Node. The
protocol, the sessions and the persisted state are the same Rust the native
clients run, compiled to WebAssembly; this package is the TypeScript head
on it (decision 0090).

```ts
import { Tacenta } from "@tacenta/sdk";

const tenant = await Tacenta.connect("tct_your_api_key");
await tenant.signUp("alice", "correct horse");
const alice = await tenant.signIn("alice", "correct horse");

const bob = await alice.find("bob");
if (bob) await alice.send(bob, "hello");
for await (const m of alice.inbound()) console.log(m.from, m.text());

// Keep the identity and sessions across runs.
const state = await alice.exportState();
const again = await tenant.signInWithState("alice", "correct horse", state);
```

`inbound()` is the client's messages one at a time as they arrive, for
`for await`; `receive()` is the same as batches, awaiting the next
non-empty one. Run one loop per client: a message goes to whichever is
waiting. A pending `receive` or `inbound` does not hold the client, so a
`send` from elsewhere goes through meanwhile.

`Tacenta.connect` fetches the server's service document
(`/.well-known/tacenta`) and reaches the four services over the WebSocket
carriage it names: one `wss://` socket per service, terminated at the
server's edge, so a page needs nothing but HTTPS. For a local development
gateway pass `{ documentUrl: "http://127.0.0.1:4780/.well-known/tacenta" }`.

## What the page can see

This head runs inside the page, and the page is the trust boundary: every
script that runs on it is, to this SDK, the app. A script on the page can
read the module's memory (the API key, a password during sign-in, the
identity and session keys, plaintexts), replace the global `WebSocket` or
`fetch` the SDK uses, and read whatever the app stores. Content-security
policy, a strict set of third-party scripts, and a Worker for the SDK are
the page's defences; the SDK has none of its own against the page. On Node,
`NODE_TLS_REJECT_UNAUTHORIZED=0` disables the certificate check the whole
design rests on.

`exportState` returns the device's identity and session secrets as bytes.
Keep them app-private and encrypted at rest. In a browser the only store is
IndexedDB, which is neither encrypted nor private from same-origin scripts:
an app that needs protection at rest wraps the bytes under a key the user
unlocks (`crypto.subtle`) and treats the state as compromised if the origin
is. There is no sealed (rollback-resistant) state on this head yet.

## Errors

Everything this package throws is a `TacentaError` with a `kind` to branch
on and the detail in `message`. The kinds are the same on every head and
described in `sdk/SURFACE.md`; a kind may be added, so handle the ones you
branch on and let the rest fall through.

```ts
import { Tacenta, TacentaError } from "@tacenta/sdk";

try {
  await tenant.signIn("alice", password);
} catch (e) {
  if (e instanceof TacentaError && e.kind === "signInRefused") showPasswordPrompt();
  else throw e;
}
```

## Building

```bash
npm run build:wasm   # compiles crates/tacenta-wasm with wasm-pack into wasm/
npm run build        # compiles src/ into dist/
```

`wasm/` and `dist/` are build output and not tracked. The end-to-end test
needs a harness build of the module, which adds tenant creation for the
test's own use and is not what the package ships (`npm pack` rebuilds the
module without it first):

```bash
npm run build:wasm:harness && npm run build && npm test
```

It builds and starts a local `tacenta-server` and `tacenta-gateway` from
the workspace, then signs two users up and in, messages both ways and
resumes from persisted state, entirely through the carriage. The same run
also checks the package against the SDK surface manifest,
`sdk/surface.json`, in both directions: every call the manifest says this
head has must exist, and every public method must be in the manifest.

`conformance/run.mjs` is the same conversation against a real server, for
the conformance run every release tag makes against hosted Tacenta
(the release pipeline); it prints a transcript and needs a
tenant's API key:

```bash
TACENTA_API_KEY=tct_... node conformance/run.mjs
```

## Not yet

The package is not yet published to a registry (decision 0090). Sealed state (the rollback-resistant path, decision 0078) and the
secure-store hook are not on this head yet.

The protocol has not yet had an independent audit. What is proven and what
is assumed is on the assurance page, and a package's claims may not outrun
it (decision 0090).
