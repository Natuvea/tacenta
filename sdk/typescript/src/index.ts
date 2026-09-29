/**
 * @tacenta/sdk: end-to-end encrypted messaging for your app, in browsers
 * and Node (decision record 0090, step 4).
 *
 * The protocol, the sessions and the persisted state are the same Rust the
 * native clients run, compiled to WebAssembly. This file is the head: it
 * fetches the server's service document, opens one WebSocket per service
 * when the client asks, and gives the Rust facade a JavaScript shape.
 *
 *     const tenant = await Tacenta.connect("tct_your_api_key");
 *     await tenant.signUp("alice", "correct horse");
 *     const alice = await tenant.signIn("alice", "correct horse");
 *     const bob = await alice.find("bob");
 *     if (bob) await alice.send(bob, "hello");
 *     for await (const m of alice.inbound()) console.log(m.from, m.text());
 */

import { TacentaHandle, Client as WasmClient } from "../wasm/tacenta.js";
import { openSocket, ready } from "./socket.js";

/** Where the document that names the services lives on a server. */
export const WELL_KNOWN_PATH = "/.well-known/tacenta";

/** The hosted service. */
export const DEFAULT_SERVER = "tacenta.com";

/** The service document a server publishes; `ws` is what this head uses. */
export interface ServiceDocument {
  version: number;
  server_name: string;
  directory: string;
  relay: string;
  accounts: string;
  provisioning: string;
  tls: "none" | "web-pki" | { "private-ca": { trust_anchors_pem: string } };
  ws?: string;
}

/**
 * The kinds of `TacentaError`, the same on every head (decision record
 * 0090); `sdk/SURFACE.md` describes each. A kind may be added, so handle
 * the ones you branch on and let the rest fall through.
 */
export const ERROR_KINDS = [
  "network",
  "discovery",
  "unknownTenant",
  "usernameTaken",
  "invalidUsername",
  "weakPassword",
  "signUpRefused",
  "signInRefused",
  "identityMismatch",
  "notFound",
  "rateLimited",
  "serverFailure",
  "state",
  "storeUnavailable",
  "invalidArgument",
  "internal",
] as const;

/** What a sign-in found; see `Client.restoreOutcome`. */
export const RESTORE_OUTCOMES = ["fresh", "resumed", "sessionsDiscarded"] as const;
export type RestoreOutcome = (typeof RESTORE_OUTCOMES)[number];

/** What an app can branch on: the kind of a `TacentaError`. */
export type ErrorKind = (typeof ERROR_KINDS)[number];

/** Every error this package throws. */
export class TacentaError extends Error {
  constructor(
    /** The kind, to branch on. */
    public readonly kind: ErrorKind,
    message: string,
  ) {
    super(message);
    this.name = "TacentaError";
  }
}

function isKind(value: unknown): value is ErrorKind {
  return typeof value === "string" && (ERROR_KINDS as readonly string[]).includes(value);
}

/**
 * Run a call against the wasm module and make whatever it throws a
 * `TacentaError`: the module throws an Error carrying a `kind`; anything
 * else (a failed instantiation, a bad argument the glue rejects) is
 * `internal` with its message.
 */
async function wrap<T>(call: () => T | Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (thrown) {
    if (thrown instanceof TacentaError) throw thrown;
    const kind = (thrown as { kind?: unknown } | null)?.kind;
    const message = thrown instanceof Error ? thrown.message : String(thrown);
    throw new TacentaError(isKind(kind) ? kind : "internal", message);
  }
}

/** A message received by a client. */
export class Message {
  constructor(
    /** The sender, `user/device`. */
    public readonly from: string,
    /** The decrypted bytes. */
    public readonly plaintext: Uint8Array,
  ) {}

  /** The plaintext as UTF-8 text. */
  text(): string {
    return new TextDecoder().decode(this.plaintext);
  }
}

export interface ConnectOptions {
  /** The server's host name; the document is fetched from `https://{server}/.well-known/tacenta`. */
  server?: string;
  /** The document's URL, for a local development gateway (`http://127.0.0.1:4780/.well-known/tacenta`). */
  documentUrl?: string;
  /**
   * A document already in hand; skips the fetch and the origin check, so
   * the caller vouches for it. A plaintext (`ws://`) carriage is still
   * refused unless it is on loopback or `allowPlaintext` is set.
   */
  document?: ServiceDocument;
  /** Accept a plaintext carriage off loopback in `document`: a LAN test rig, never production. */
  allowPlaintext?: boolean;
}

/** A signed-in client: one user on one device. */
export class Client {
  /** @internal */
  constructor(private readonly inner: WasmClient) {}

  /** This client's address, `user/device`. */
  get address(): string {
    return this.inner.address();
  }

  /**
   * What the sign-in found: `"fresh"` (no sessions restored), `"resumed"`,
   * or `"sessionsDiscarded"` (a restored state was older than one already
   * seen, so its sessions were dropped and the identity kept). This head
   * has no sealed restore, so it reports the first two.
   */
  async restoreOutcome(): Promise<RestoreOutcome> {
    const raw = await wrap(() => this.inner.restoreOutcome());
    return (RESTORE_OUTCOMES as readonly string[]).includes(raw) ? (raw as RestoreOutcome) : "sessionsDiscarded";
  }

  /** Look a username up in the tenant; the address to send to, or undefined. */
  async find(username: string): Promise<string | undefined> {
    return await wrap(() => this.inner.find(username));
  }

  /** Send to an address (`user/device`): bytes, or text encoded as UTF-8. */
  async send(to: string, plaintext: Uint8Array | string): Promise<void> {
    if (typeof plaintext !== "string" && !(plaintext instanceof Uint8Array)) {
      // An ArrayBuffer or a DataView has no `length`, and the module would
      // copy nothing and send an empty message without a word.
      throw new TacentaError("invalidArgument", "plaintext must be a string or a Uint8Array");
    }
    const bytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    await wrap(() => this.inner.send(to, bytes));
  }

  /** Fetch and decrypt what is waiting. */
  async receive(): Promise<Message[]> {
    const raw = await wrap(() => this.inner.receive());
    return raw.map((m) => new Message(m.from, m.plaintext));
  }

  /**
   * Inbound messages one at a time, as they arrive: `receive` flattened,
   * for `for await (const m of client.inbound())`. A message goes to
   * whichever loop is running, so run one per client. It ends only by
   * throwing.
   */
  async *inbound(): AsyncGenerator<Message, void, void> {
    for (;;) {
      for (const m of await this.receive()) yield m;
    }
  }

  /**
   * The identity and live sessions, to persist and resume with
   * `Tacenta.signInWithState`. Keeping the same identity across runs is
   * what lets conversations continue.
   *
   * The bytes carry private keys: keep them app-private and encrypted at
   * rest (IndexedDB is neither on its own), store only the latest copy,
   * and export again after every send and receive, since a restore of an
   * older copy rewinds sessions.
   */
  async exportState(): Promise<Uint8Array> {
    return await wrap(() => this.inner.exportState());
  }
}

/** One tenant's handle: build it once, sign users up and in through it. */
export class Tacenta {
  /** @internal */
  private constructor(
    private readonly handle: TacentaHandle,
    /** The document the handle was built from. */
    public readonly document: ServiceDocument,
  ) {}

  /**
   * Connect to a server: fetch its service document and prepare to reach
   * its services over the WebSocket carriage the document names.
   */
  static async connect(apiKey: string, options: ConnectOptions = {}): Promise<Tacenta> {
    await wrap(ready);
    if (options.document) {
      // A document the caller vouches for: no origin check, like the native
      // client's from_document.
      const handle = await wrap(() =>
        TacentaHandle.fromDocument(
          apiKey,
          JSON.stringify(options.document),
          openSocket,
          options.allowPlaintext ?? false,
        ),
      );
      return new Tacenta(handle, options.document);
    }
    const url = documentUrl(options);
    const document = await fetchDocument(url);
    // The guarded path: the Rust side holds the document to what a document
    // from that origin may say, with the native client's rule and tests.
    const handle = await wrap(() =>
      TacentaHandle.connect(apiKey, url, JSON.stringify(document), openSocket),
    );
    return new Tacenta(handle, document);
  }

  /** Create a user in this tenant. */
  async signUp(username: string, password: string): Promise<void> {
    await wrap(() => this.handle.signUp(username, password));
  }

  /** Sign a user in on `device` with a fresh device identity. */
  async signIn(username: string, password: string, device = 1): Promise<Client> {
    checkDevice(device);
    return new Client(await wrap(() => this.handle.signIn(username, password, device)));
  }

  /** Sign in resuming state from `Client.exportState`. */
  async signInWithState(
    username: string,
    password: string,
    state: Uint8Array,
    device = 1,
  ): Promise<Client> {
    checkDevice(device);
    if (!(state instanceof Uint8Array)) {
      throw new TacentaError("invalidArgument", "state must be the Uint8Array exportState returned");
    }
    return new Client(
      await wrap(() => this.handle.signInWithState(username, password, device, state)),
    );
  }

}

/**
 * A device number is one byte on the wire and 1 is the first; the module
 * would otherwise take the value modulo 256 and sign in the wrong device.
 */
function checkDevice(device: number): void {
  if (!Number.isInteger(device) || device < 1 || device > 255) {
    throw new TacentaError("invalidArgument", `device must be an integer from 1 to 255, not ${device}`);
  }
}

/** A URL for an error message: no userinfo, and never very long. */
function shown(url: string): string {
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    return u.href.slice(0, 256);
  } catch {
    return url.slice(0, 256);
  }
}

function documentUrl(options: ConnectOptions): string {
  if (options.documentUrl) return options.documentUrl;
  return `https://${options.server ?? DEFAULT_SERVER}${WELL_KNOWN_PATH}`;
}

async function fetchDocument(url: string): Promise<ServiceDocument> {
  let res: Response;
  try {
    // No redirects (a document must come from the origin it is checked
    // against) and no cookies (the fetch carries no ambient authority).
    res = await fetch(url, {
      headers: { accept: "application/json" },
      redirect: "error",
      credentials: "omit",
    });
  } catch (e) {
    throw new TacentaError("discovery", `service discovery failed: ${shown(url)}: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!res.ok) {
    throw new TacentaError("discovery", `service discovery failed: ${shown(url)}: ${res.status} ${res.statusText}`);
  }
  try {
    return (await res.json()) as ServiceDocument;
  } catch (e) {
    throw new TacentaError("discovery", `service discovery failed: ${shown(url)}: ${e instanceof Error ? e.message : String(e)}`);
  }
}
