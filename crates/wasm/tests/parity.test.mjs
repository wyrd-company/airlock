// Parity: the same audit, natively and as WebAssembly, against the same
// recorded GitHub responses, gives the same findings document.
//
// One local HTTP server replays the recording. The native build
// (examples/parity_native.rs, through reqwest) and the module (under Node,
// through the shipped fetch host) both audit through it. The documents are
// compared whole, apart from TIME_VARYING, the fields docs/wasm.md names.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { before, after, test } from "node:test";

import { fetchHost } from "../js/host.mjs";
import { loadModule, readRecording } from "./support.mjs";

/** Fields that differ between two live runs. docs/wasm.md lists the same. */
export const TIME_VARYING = [["repository", "settings_observed_at"]];

let airlock;
let recording;
let server;
let base;
const served = { native: [], wasm: [] };
const unexpected = [];
let who = "native";

before(async () => {
  airlock = await loadModule();
  recording = readRecording("audit-airlock.json");
  server = createServer((request, response) => {
    const exchange = recording.exchanges.find(
      (candidate) => candidate.method === request.method && candidate.path === request.url,
    );
    if (!exchange || request.headers.authorization !== `Bearer ${recording.token}`) {
      unexpected.push(`${who}: ${request.method} ${request.url}`);
      response.writeHead(404, { "content-type": "application/json" });
      response.end('{"message":"Not Found"}');
      return;
    }
    served[who].push(`${request.method} ${request.url}`);
    const headers = exchange.headers.map(([name, value]) => [
      name,
      name === "link" ? value.replaceAll("https://api.github.com", base) : value,
    ]);
    response.writeHead(exchange.status, headers.flat());
    response.end(exchange.body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server?.close());

function auditRequest() {
  return JSON.stringify({ token: recording.token, ...recording.request, githubApi: base });
}

function runNative() {
  const binary = process.env.AIRLOCK_PARITY_NATIVE;
  assert.ok(binary, "AIRLOCK_PARITY_NATIVE names the native parity binary (task wasm:test builds it)");
  return new Promise((resolve, reject) => {
    const child = spawn(binary, [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0 ? resolve(stdout) : reject(new Error(`native run exited ${code}: ${stderr}`)),
    );
    child.stdin.end(auditRequest());
  });
}

function withoutTimeVarying(document) {
  const copy = structuredClone(document);
  for (const path of TIME_VARYING) {
    let parent = copy;
    for (const key of path.slice(0, -1)) parent = parent?.[key];
    if (parent) delete parent[path.at(-1)];
  }
  return copy;
}

test("the native and WebAssembly builds give the same findings document", async () => {
  who = "native";
  const native = JSON.parse(await runNative());
  who = "wasm";
  const wasm = JSON.parse(await airlock.audit(fetchHost(), auditRequest()));

  assert.deepEqual(unexpected, [], "a run asked for a response that is not recorded");
  // Not a trivial document: the recording is a full audit.
  assert.ok(native.findings.length >= 50, `${native.findings.length} findings`);
  assert.deepEqual(native.run_errors, []);
  assert.deepEqual(served.wasm, served.native, "the two runs made different requests");
  assert.deepEqual(withoutTimeVarying(wasm), withoutTimeVarying(native));
  // From one recording the time-varying fields agree too; they are excluded
  // only because two live runs would not.
  assert.deepEqual(wasm, native);
});
