// A host for the Airlock module on the platform's own fetch: Node 22 or
// later, the JavaScript action, and a Cloudflare Worker.
//
// The module calls `fetch`, `sleep` and `now` on the object this returns,
// and nothing else. See docs/wasm.md for the contract.

/** An error with the `name` the module reads a failure's kind from. */
function named(name, message) {
  const error = new Error(message);
  error.name = name;
  return error;
}

/**
 * Read a body, abandoning it at `max` bytes.
 * @param {Response} response
 * @param {number} max
 */
async function readCapped(response, max) {
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      throw named("TooLargeError", `the response exceeded the ${max} byte limit and was abandoned`);
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/**
 * Build the host object.
 *
 * Each part can be replaced, which is how tests run the module against
 * fakes and a fake clock.
 *
 * @param {{
 *   fetch?: typeof globalThis.fetch,
 *   sleep?: (ms: number) => Promise<void>,
 *   now?: () => number,
 * }} [parts]
 */
export function fetchHost(parts = {}) {
  const fetchImpl = parts.fetch ?? globalThis.fetch;
  const sleep = parts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const now = parts.now ?? (() => Date.now());
  return {
    async fetch(request) {
      const signal = AbortSignal.timeout(Math.max(1, request.timeoutMs));
      let response;
      try {
        response = await fetchImpl(request.url, {
          method: request.method,
          headers: request.headers,
          body: request.body,
          redirect: request.redirect,
          signal,
        });
      } catch (error) {
        // The message names no header and no body; the URL is the engine's.
        if (error?.name === "TimeoutError" || signal.aborted) {
          throw named("TimeoutError", `the request to ${request.url} timed out`);
        }
        // fetch rejects with a TypeError for a network failure.
        if (error instanceof TypeError) {
          throw named("ConnectError", `the request to ${request.url} could not connect`);
        }
        throw named("Error", `the request to ${request.url} failed`);
      }
      let body;
      try {
        body = await readCapped(response, request.maxResponseBytes);
      } catch (error) {
        if (error?.name === "TooLargeError") throw error;
        if (error?.name === "TimeoutError" || signal.aborted) {
          throw named("TimeoutError", `the answer from ${request.url} timed out`);
        }
        throw named("Error", `reading the answer from ${request.url} failed`);
      }
      // Headers joins a repeated field with ", ", so a host on fetch hands
      // the engine one value where the field repeated.
      return { status: response.status, headers: [...response.headers], body };
    },
    sleep,
    now,
  };
}
