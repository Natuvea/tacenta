/**
 * Test-only: create a tenant on a local server through the carriage, so the
 * end-to-end test can start from an empty server. Works only against a
 * harness build of the module (`npm run build:wasm:harness`); the package's
 * `exports` map does not include this file, and the published module has no
 * such method.
 */

import { TacentaHandle } from "../wasm/tacenta.js";
import { openSocket, ready } from "./socket.js";

export async function signUpTenant(
  documentUrl: string,
  username: string,
  email: string,
  password: string,
): Promise<string> {
  await ready();
  const res = await fetch(documentUrl);
  const document = await res.text();
  const handle = await TacentaHandle.connect("tct_none_yet", documentUrl, document, openSocket);
  const h = handle as unknown as {
    signUpTenant?: (u: string, e: string, p: string) => Promise<string>;
  };
  if (!h.signUpTenant) throw new Error("not a harness build of the module");
  return await h.signUpTenant(username, email, password);
}
