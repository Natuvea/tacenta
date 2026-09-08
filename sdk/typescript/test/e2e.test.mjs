// The head end to end: a local server and gateway, and two users who sign
// up, sign in, message each other and resume from persisted state, all
// through the WebSocket carriage. Needs a harness build of the module
// (`npm run build:wasm:harness`) so the test can create its tenant.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer, connect as tcpConnect } from "node:net";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const processes = [];

async function freePort() {
  return await new Promise((resolve) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function waitForPort(port, attempts = 100) {
  for (let i = 0; i < attempts; i++) {
    const up = await new Promise((resolve) => {
      const sock = tcpConnect({ host: "127.0.0.1", port }, () => {
        sock.destroy();
        resolve(true);
      });
      sock.on("error", () => resolve(false));
    });
    if (up) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`port ${port} did not come up`);
}

async function waitFor(url, attempts = 100) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json();
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not come up`);
}

let documentUrl;

before(async () => {
  execFileSync("cargo", ["build", "-q", "-p", "tacenta-server", "-p", "tacenta-gateway"], {
    cwd: repo,
    stdio: "inherit",
  });
  const ports = {
    TACENTA_DIRECTORY_PORT: String(await freePort()),
    TACENTA_RELAY_PORT: String(await freePort()),
    TACENTA_ACCOUNTS_PORT: String(await freePort()),
    TACENTA_PROVISIONING_PORT: String(await freePort()),
  };
  const gatewayPort = await freePort();
  const bin = (name) => path.join(repo, "target", "debug", name);
  const server = spawn(bin("tacenta-server"), [], {
    env: { ...process.env, ...ports, TACENTA_BIND: "127.0.0.1" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const gateway = spawn(bin("tacenta-gateway"), [], {
    env: { ...process.env, ...ports, GATEWAY_BIND: `127.0.0.1:${gatewayPort}` },
    stdio: ["ignore", "ignore", "inherit"],
  });
  processes.push(server, gateway);
  documentUrl = `http://127.0.0.1:${gatewayPort}/.well-known/tacenta`;
  const doc = await waitFor(documentUrl);
  assert.equal(doc.ws, `ws://127.0.0.1:${gatewayPort}/v1/ws`);
  // The gateway answers before the server has bound its ports; wait for
  // those too, or the first upgrade is a 502 the socket reports as a close.
  for (const p of Object.values(ports)) await waitForPort(Number(p));
}, { timeout: 600_000 });

after(() => {
  for (const p of processes) p.kill();
});

test("two users message through the carriage and resume from state", async () => {
  const { Tacenta } = await import("../dist/index.js");
  const { signUpTenant } = await import("../dist/harness.js");
  const { conversation } = await import("../conformance/conversation.mjs");
  const apiKey = await signUpTenant(documentUrl, "acme", "admin@acme.example", "correct horse");
  assert.match(apiKey, /^tct_/);

  const tenant = await Tacenta.connect(apiKey, { documentUrl });
  // The same conversation the conformance run makes against hosted Tacenta.
  const { alice, bob } = await conversation(tenant);
  assert.match(alice, /^acme\/conform-a-[0-9a-f]+\/1$/);
  assert.match(bob, /^acme\/conform-b-[0-9a-f]+\/1$/);
}, { timeout: 120_000 });
