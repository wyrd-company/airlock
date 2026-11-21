// main.mjs on its own, with a fake runner and a fake engine: the action's
// own guards, independent of the engine's. The engine redacts what it
// returns; these show the action would not let a token through even if it
// did not.

import assert from "node:assert/strict";
import { test } from "node:test";

import { run } from "../src/main.mjs";

const TOKEN = "ghs_15368_eyJhbGciOiJub25lIn0.eyJTWU5USEVUSUMiOnRydWV9.bWFpbi10ZXN0_MARKER6";

function runner({ inputs = {}, audit }) {
  const written = { secrets: [], outputs: {}, exported: {}, log: [], failed: [], files: {}, uploads: [] };
  const io = {
    input: (name) => (inputs[name] ?? "").trim(),
    env: { GITHUB_REPOSITORY: "wyrd-company/airlock", RUNNER_TEMP: "/runner/temp", GITHUB_ACTIONS: "true" },
    setSecret: (value) => written.secrets.push(value),
    setOutput: (name, value) => (written.outputs[name] = value),
    exportVariable: (name, value) => (written.exported[name] = value),
    info: (message) => written.log.push(message),
    error: (message) => written.log.push(message),
    warning: (message) => written.log.push(message),
    setFailed: (message) => written.failed.push(message),
    writeFile: (path, text) => (written.files[path] = text),
    audit,
    upload: async (path) => written.uploads.push(path),
  };
  return { io, written };
}

function assertClean(written) {
  const everything = JSON.stringify({ ...written, secrets: [] });
  assert.ok(!everything.includes(TOKEN), everything.slice(0, 400));
}

test("a document that carries a token is redacted before it is written, printed or uploaded", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN, "run-token": TOKEN },
    audit: async () =>
      JSON.stringify({ outcome: "conformant", complete: true, document: `{"echo":"${TOKEN}"}` }),
  });
  await run(io);
  assert.deepEqual(written.secrets, [TOKEN, TOKEN]);
  assert.match(Object.values(written.files)[0], /\[redacted\]/);
  assert.deepEqual(written.failed, []);
  assertClean(written);
});

test("an engine error that carries a token is redacted in the incomplete document and the log", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN, "run-token": TOKEN },
    audit: async () => {
      const error = new Error(`refused ${TOKEN}`);
      error.kind = "refused";
      throw error;
    },
  });
  await run(io);
  assert.equal(written.outputs.outcome, "incomplete");
  assert.equal(written.failed.length, 1);
  assertClean(written);
});

test("an upload error that carries a token is redacted", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN, "run-token": TOKEN },
    audit: async () => JSON.stringify({ outcome: "conformant", complete: true, document: "{}" }),
  });
  io.upload = async () => {
    throw new Error(`upload refused ${TOKEN}`);
  };
  await run(io);
  assert.match(written.failed[0], /could not be uploaded/);
  assertClean(written);
});

test("an outcome the engine does not name is incomplete, never a pass", async () => {
  for (const outcome of ["", "passed", undefined]) {
    const { io, written } = runner({
      inputs: { token: TOKEN, "run-token": TOKEN },
      audit: async () => JSON.stringify({ outcome, complete: true, document: "{}" }),
    });
    await run(io);
    assert.equal(written.outputs.outcome, "incomplete");
    assert.equal(written.outputs.complete, "false");
    assert.equal(written.failed.length, 1);
  }
});
