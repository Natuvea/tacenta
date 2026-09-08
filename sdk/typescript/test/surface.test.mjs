// The TypeScript head checks itself against the surface manifest (decision
// 0090, choice 6): every symbol the manifest says this head exposes must be
// a method on the built package, and every public method on the package's
// two classes must be in the manifest, so the head can neither fall behind
// the manifest nor grow past it unrecorded.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(here, "../../surface.json"), "utf8"));

function methodsOf(cls) {
  const names = new Set();
  for (const owner of [cls, cls.prototype]) {
    for (const name of Object.getOwnPropertyNames(owner)) {
      if (["length", "name", "prototype", "constructor"].includes(name)) continue;
      names.add(name);
    }
  }
  return names;
}

test("the TypeScript head matches the manifest, both ways", async () => {
  const { Tacenta, Client } = await import("../dist/index.js");
  const classes = { Tacenta, Client };
  const inManifest = new Map(Object.keys(classes).map((k) => [k, new Set()]));
  const missing = [];
  for (const object of manifest.objects) {
    for (const call of object.calls) {
      if (!call.typescript) continue;
      const [cls, name] = call.typescript.split(".");
      inManifest.get(cls).add(name);
      if (!methodsOf(classes[cls]).has(name)) missing.push(call.typescript);
    }
  }
  assert.deepEqual(missing, [], "manifest names symbols the package lacks");
  for (const [cls, ctor] of Object.entries(classes)) {
    const extra = [...methodsOf(ctor)].filter((n) => !inManifest.get(cls).has(n));
    assert.deepEqual(extra, [], `${cls} exposes methods the manifest does not list`);
  }
});

test("the TypeScript error kinds match the manifest, both ways", async () => {
  const { TacentaError, ERROR_KINDS } = await import("../dist/index.js");
  assert.equal(typeof TacentaError, "function", "TacentaError is exported");
  // ERROR_KINDS is the one list the ErrorKind type and the runtime check
  // both derive from, so comparing it is comparing both.
  const named = manifest.errors.kinds.map((k) => JSON.parse(k.typescript));
  assert.deepEqual([...ERROR_KINDS].sort(), [...named].sort(), "ERROR_KINDS and the manifest differ");
});
