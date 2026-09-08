// What ships must lack the test harness: the module built with
// `npm run build:wasm` (no harness feature) exposes no tenant creation, and
// the package's file list carries no harness code. Runs only when
// TACENTA_SHIPPED=1, against that build, so `npm test` on a harness build
// does not fail it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const shipped = process.env.TACENTA_SHIPPED === "1";

test("the shipped module has no tenant creation", { skip: !shipped }, async () => {
  const { TacentaHandle } = await import("../wasm/tacenta.js");
  assert.equal(TacentaHandle.prototype.signUpTenant, undefined, "signUpTenant is the harness's, not the package's");
});

test("the package carries no harness file", { skip: !shipped }, () => {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: path.join(here, ".."),
    encoding: "utf8",
  });
  const files = JSON.parse(out)[0].files.map((f) => f.path);
  assert.ok(files.length > 0, "npm pack lists files");
  assert.deepEqual(files.filter((f) => /harness/.test(f)), [], "no harness file in the tarball");
});
