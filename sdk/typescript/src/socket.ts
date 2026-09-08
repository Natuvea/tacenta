/**
 * The two things the WebAssembly module asks of JavaScript: load it, and
 * open a socket when told to. Internal to the package; not exported.
 */

import init, { Channel } from "../wasm/tacenta.js";

/**
 * What the Rust side asks of JavaScript: open a socket at `url`, push what
 * it receives into `channel`, and hand back `send` and `close`. Bytes sent
 * before the socket opens are queued.
 */
export function openSocket(
  url: string,
  channel: Channel,
): { send(bytes: Uint8Array): void; close(): void } {
  const ws = new WebSocket(url);
  ws.binaryType = "arraybuffer";
  let open = false;
  const queue: Uint8Array[] = [];
  ws.onopen = () => {
    open = true;
    for (const bytes of queue) ws.send(bytes);
    queue.length = 0;
  };
  ws.onmessage = (event: MessageEvent) => {
    channel.push(new Uint8Array(event.data as ArrayBuffer));
  };
  ws.onclose = () => channel.close();
  ws.onerror = () => channel.close();
  return {
    send(bytes: Uint8Array) {
      if (open) ws.send(bytes);
      else queue.push(bytes.slice());
    },
    close() {
      ws.close();
    },
  };
}

let initialised: Promise<void> | undefined;

/** Load the WebAssembly module once: from the file next to it in Node, over fetch in a browser. */
export function ready(): Promise<void> {
  if (!initialised) {
    initialised = (async () => {
      const isNode = typeof process !== "undefined" && process.versions?.node !== undefined;
      if (isNode) {
        const { readFile } = await import("node:fs/promises");
        const bytes = await readFile(new URL("../wasm/tacenta_bg.wasm", import.meta.url));
        await init({ module_or_path: bytes });
      } else {
        await init();
      }
    })();
  }
  return initialised;
}
