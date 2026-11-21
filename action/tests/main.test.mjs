// main.mjs on its own, with a fake runner and a fake engine: the action's
// own guards, independent of the engine's. The engine redacts what it
// returns; these show the action would not let a token through even if it
// did not.

import assert from "node:assert/strict";
import { test } from "node:test";

import { run } from "../src/main.mjs";

const TOKEN = "ghu_SYNTHETICcallerTOKEN0123456789abcdefMARKER6";
/** The run's own token, distinct from `token`, as action.yml's step env holds it. */
const RUN = "ghs_15368_eyJhbGciOiJub25lIn0.eyJTWU5USEVUSUMiOnRydWV9.bWFpbi10ZXN0_MARKER8";

function runner({ inputs = {}, audit, env = {} }) {
  const written = { secrets: [], outputs: {}, exported: {}, log: [], failed: [], files: {}, uploads: [] };
  const io = {
    input: (name) => (inputs[name] ?? "").trim(),
    env: {
      GITHUB_REPOSITORY: "wyrd-company/airlock",
      RUNNER_TEMP: "/runner/temp",
      GITHUB_ACTIONS: "true",
      AIRLOCK_RUN_TOKEN: RUN,
      AIRLOCK_JOB_CHECK_RUN_ID: "7",
      ...env,
    },
    setSecret: (value) => written.secrets.push(value),
    setOutput: (name, value) => (written.outputs[name] = value),
    exportVariable: (name, value) => (written.exported[name] = value),
    info: (message) => written.log.push(message),
    error: (message) => written.log.push(message),
    warning: (message) => written.log.push(message),
    setFailed: (message) => written.failed.push(message),
    writeFile: (path, text) => (written.files[path] = text),
    audit,
    stage: (path, extension) => {
      written.uploads.push({ path, extension });
      return "/runner/temp/airlock-artifact-x";
    },
  };
  return { io, written };
}

function assertClean(written) {
  const everything = JSON.stringify({ ...written, secrets: [] });
  for (const secret of [TOKEN, RUN]) assert.ok(!everything.includes(secret), everything.slice(0, 400));
}

test("a document that carries a token is redacted before it is written, printed or uploaded", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN },
    audit: async () =>
      JSON.stringify({ outcome: "conformant", complete: true, document: `{"echo":"${TOKEN}","run":"${RUN}"}` }),
  });
  await run(io);
  // Each masked on its own, before anything else.
  assert.deepEqual(written.secrets, [TOKEN, RUN]);
  assert.equal(Object.values(written.files)[0].match(/\[redacted\]/g).length, 2);
  assert.match(Object.values(written.files)[0], /\[redacted\]/);
  assert.deepEqual(written.failed, []);
  assertClean(written);
});

test("an engine error that carries a token is redacted in the incomplete document and the log", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN },
    audit: async () => {
      const error = new Error(`refused ${TOKEN} bound to ${RUN}`);
      error.kind = "refused";
      throw error;
    },
  });
  await run(io);
  assert.equal(written.outputs.outcome, "incomplete");
  assert.equal(written.failed.length, 1);
  assertClean(written);
});

test("a staging error that carries a token is redacted and fails the step", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN },
    audit: async () => JSON.stringify({ outcome: "conformant", complete: true, document: "{}" }),
  });
  io.stage = () => {
    throw new Error(`staging refused ${TOKEN} ${RUN}`);
  };
  await run(io);
  assert.match(written.failed[0], /could not be staged for the airlock-findings-7 artifact/);
  assertClean(written);
});

test("an outcome the engine does not name is incomplete, never a pass", async () => {
  for (const outcome of ["", "passed", undefined]) {
    const { io, written } = runner({
      inputs: { token: TOKEN },
      audit: async () => JSON.stringify({ outcome, complete: true, document: "{}" }),
    });
    await run(io);
    assert.equal(written.outputs.outcome, "incomplete");
    assert.equal(written.outputs.complete, "false");
    assert.equal(written.failed.length, 1);
  }
});

test("the run's token comes from the step's env, never from an input", async () => {
  let sent;
  const { io } = runner({
    inputs: { token: TOKEN, "run-token": "ghs_999999_FORGED.forged-token_value" },
    audit: async (request) => {
      sent = JSON.parse(request);
      return JSON.stringify({ outcome: "conformant", complete: true, document: "{}" });
    },
  });
  await run(io);
  assert.equal(sent.runToken, RUN);
  assert.equal(sent.token, TOKEN);
});

test("the artifact is named for the job's check run", async () => {
  const { io, written } = runner({
    inputs: { token: TOKEN },
    audit: async () => JSON.stringify({ outcome: "conformant", complete: true, document: "{}" }),
  });
  await run(io);
  assert.equal(written.outputs.artifact, "airlock-findings-7");
  assert.equal(written.outputs["artifact-directory"], "/runner/temp/airlock-artifact-x");
});
