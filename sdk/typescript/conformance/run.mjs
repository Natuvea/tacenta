#!/usr/bin/env node
// The TypeScript head's conformance run (decision 0090, choice 6): the
// conversation in conversation.mjs against whichever server the document URL
// names (hosted Tacenta by default), printing a transcript a reader can check
// line by line. Exit status is the verdict. Not a unit test, and not under
// test/ so the test runner does not pick it up: it needs a real tenant.
//
//   TACENTA_API_KEY=tct_... node conformance/run.mjs
//   TACENTA_DOCUMENT_URL=http://127.0.0.1:4780/.well-known/tacenta ...

import { Tacenta } from "../dist/index.js";
import { conversation } from "./conversation.mjs";

const apiKey = process.env.TACENTA_API_KEY;
const documentUrl = process.env.TACENTA_DOCUMENT_URL ?? "https://tacenta.com/.well-known/tacenta";
if (!apiKey) {
  console.error("TACENTA_API_KEY is not set");
  process.exit(2);
}

const started = Date.now();
const log = (line) => console.log(`${String(Date.now() - started).padStart(6)}ms  ${line}`);

try {
  log(`document ${documentUrl}`);
  const tenant = await Tacenta.connect(apiKey, { documentUrl });
  log(`carriage ${tenant.document.ws}`);
  await conversation(tenant, log);
  log("PASS");
  // The clients' sockets stay open and would keep the event loop alive.
  process.exit(0);
} catch (e) {
  log(`FAIL ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
