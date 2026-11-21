// The action end to end: dist/index.mjs, as action.yml's step starts it,
// against a local server that is GitHub's API, replaying the module's
// recording. The step stages the report for action.yml's upload-artifact
// step, which runs only on GitHub; the CI jobs and audit.yml prove that part.
// Every token below is a synthetic marker.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { after, before, test } from "node:test";

import {
  RUN_TOKEN,
  actionsVariables,
  readRecording,
  repositoryFetch,
  repositoryRoot,
  workflowDeclaring,
} from "../../crates/wasm/tests/support.mjs";

const ENTRY = resolve(repositoryRoot, "dist/index.mjs");
const RUN_ID = "4242";
/** job.check_run_id, as action.yml hands it over. */
const CHECK_RUN_ID = "51725241954";
const ARTIFACT = `airlock-findings-${CHECK_RUN_ID}`;

let recording;
let server;
let base;
let scratch;
/** What the GitHub side of the server answers with; each test sets it. */
let github;

before(async () => {
  recording = readRecording("audit-airlock.json");
  scratch = mkdtempSync(join(tmpdir(), "airlock-action-test-"));
  server = createServer(async (request, response) => {
    for await (const _ of request);
    const url = new URL(request.url, base);
    const headers = Object.entries(request.headers).map(([name, value]) => [name, String(value)]);
    const answer = await github.fetch(url.href, { method: request.method, headers });
    response.writeHead(answer.status, Object.fromEntries(answer.headers));
    response.end(Buffer.from(await answer.arrayBuffer()));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  rmSync(scratch, { recursive: true, force: true });
});

/**
 * Run dist/index.mjs as the runner does, with `inputs` and `variables`.
 * Resolves to what the run left: its exit code, its log, its outputs, its
 * exported variables, its findings document and its artifact.
 */
async function runAction({
  inputs = {},
  variables = actionsVariables(),
  env = {},
  name = "run",
  viaStep,
  shell = "/bin/sh",
} = {}) {
  const directory = mkdtempSync(join(scratch, `${name}-`));
  const outputFile = join(directory, "output");
  const envFile = join(directory, "env");
  writeFileSync(outputFile, "");
  writeFileSync(envFile, "");
  const environment = {
    PATH: process.env.PATH,
    RUNNER_TEMP: directory,
    GITHUB_OUTPUT: outputFile,
    GITHUB_ENV: envFile,
    GITHUB_RUN_ID: RUN_ID,
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_ACTION: "airlock",
    GITHUB_API_URL: base,
    GITHUB_SERVER_URL: "https://github.com",
    // What action.yml's step sets in its own env.
    AIRLOCK_RUN_TOKEN: RUN_TOKEN,
    AIRLOCK_JOB_CHECK_RUN_ID: CHECK_RUN_ID,
    ...variables,
    ...env,
  };
  // action.yml hands each input over as INPUT_<NAME>, with `-` as `_`.
  for (const [input, value] of Object.entries(inputs)) {
    environment[`INPUT_${input.toUpperCase().replace(/-/g, "_")}`] = value;
  }
  for (const [key, value] of Object.entries(environment)) if (value === undefined) delete environment[key];

  // viaStep: through action/step.sh, as action.yml's audit step runs it, on a
  // stand-in for the pinned Node that records the environment it was given
  // and then runs this Node. "patched" runs a copy of step.sh whose pinned
  // SHA-256 is the stand-in's; "real" runs step.sh itself, whose pin the
  // stand-in cannot meet. `shell` is the program that runs it, as /bin/sh.
  let child;
  if (viaStep) {
    const nodeDir = join(directory, "node-bin");
    mkdirSync(nodeDir);
    writeFileSync(
      join(nodeDir, "node"),
      [
        "#!/bin/sh",
        'if [ "$1" = --version ]; then echo v24.22.3; exit 0; fi',
        `/usr/bin/env > '${join(directory, "node-env")}'`,
        `exec '${process.execPath}' "$@"`,
        "",
      ].join("\n"),
    );
    chmodSync(join(nodeDir, "node"), 0o755);
    environment.AIRLOCK_NODE_DIR ??= nodeDir;
    environment.AIRLOCK_NODE_VERSION ??= "24.22.3";
    environment.AIRLOCK_ACTION_PATH ??= repositoryRoot;
    environment.AIRLOCK_RUNNER_OS ??= "Linux";
    environment.AIRLOCK_NODE_ARCH ??= "x64";
    let script = join(repositoryRoot, "action/step.sh");
    if (viaStep !== "real") {
      const digest = createHash("sha256").update(readFileSync(join(nodeDir, "node"))).digest("hex");
      script = join(directory, "step.sh");
      writeFileSync(
        script,
        readFileSync(join(repositoryRoot, "action/step.sh"), "utf8").replace(
          /x64\) expected=[0-9a-f]{64}/,
          `x64) expected=${digest}`,
        ),
      );
    }
    child = spawn(shell, [script], { env: environment, cwd: directory, argv0: "sh" });
  } else {
    child = spawn(process.execPath, [ENTRY], { env: environment, cwd: directory });
  }
  let log = "";
  child.stdout.on("data", (chunk) => (log += chunk));
  child.stderr.on("data", (chunk) => (log += chunk));
  const status = await new Promise((done) => child.on("close", done));

  const outputs = parseCommandFile(readFileSync(outputFile, "utf8"));
  const exported = parseCommandFile(readFileSync(envFile, "utf8"));
  const findings = outputs["findings-location"] ? readFileSync(outputs["findings-location"], "utf8") : undefined;
  // What action.yml's upload step would upload: the staged directory, under
  // the artifact output's name.
  const staged = outputs["artifact-directory"];
  const artifact = staged ? { name: outputs.artifact, directory: staged } : undefined;
  const artifactFiles = staged
    ? Object.fromEntries(readdirSync(staged).map((file) => [file, readFileSync(join(staged, file), "utf8")]))
    : undefined;
  const nodeEnv = viaStep && existsSync(join(directory, "node-env"))
    ? readFileSync(join(directory, "node-env"), "utf8")
    : undefined;
  return { status, log, outputs, exported, findings, artifact, artifactFiles, nodeEnv, directory, raw: { outputFile, envFile } };
}

/** The `name<<delimiter` heredoc form the runner's command files use. */
function parseCommandFile(text) {
  const values = {};
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^([^<=]+)<<(.+)$/.exec(lines[index]);
    if (!match) continue;
    const [, name, delimiter] = match;
    const value = [];
    for (index += 1; lines[index] !== delimiter; index += 1) value.push(lines[index]);
    values[name] = value.join("\n");
  }
  return values;
}

/** Fail when the run left a token anywhere a person or a later step reads. */
function assertNoToken(run, tokens = [RUN_TOKEN]) {
  // An absent artifact would make "the artifact carries no token" hold for
  // nothing: every run here stages exactly one file.
  assert.ok(run.artifact?.name, "the artifact was staged and named");
  assert.equal(Object.keys(run.artifactFiles ?? {}).length, 1, "the artifact holds one file");
  for (const token of tokens) {
    // The only line that names a token is the mask command, which the
    // runner consumes; it must come before anything else is printed.
    const lines = run.log.split("\n");
    const masks = lines.filter((line) => line === `::add-mask::${token}`);
    const rest = lines.filter((line) => line !== `::add-mask::${token}`).join("\n");
    assert.ok(!rest.includes(token), `the log carries ${token}`);
    if (masks.length > 0) assert.ok(lines.slice(0, 2).includes(`::add-mask::${token}`), "the token is masked first");
    for (const [label, text] of [
      ["outputs", readFileSync(run.raw.outputFile, "utf8")],
      ["exported variables", readFileSync(run.raw.envFile, "utf8")],
      ["findings", run.findings ?? ""],
      ["artifact", JSON.stringify(run.artifactFiles ?? {})],
    ]) {
      assert.ok(!text.includes(token), `the ${label} carry ${token}`);
    }
  }
}

/** The template's `with:` block at a2470d6, with github.token resolved. */
const TEMPLATE_INPUTS = {
  mode: "repository",
  token: RUN_TOKEN,
  policy: "wyrd-company/.github:airlock/policy.yml",
};

/** The recording's policy, served from wyrd-company/.github at airlock/policy.yml. */
function organizationPolicy(path) {
  const prefix = "/repos/wyrd-company/.github/";
  if (!path.startsWith(prefix)) return undefined;
  const rest = path.slice(prefix.length).replace(/^commits\/HEAD$/, "commits/aa31121c5ead759d07c21915004de8c52b7597a7");
  const exchange = recording.exchanges.find((candidate) => candidate.path === `/repos/wyrd-company/airlock/${rest}`);
  if (!exchange) return undefined;
  let body = exchange.body;
  if (rest.startsWith("git/trees/")) {
    const tree = JSON.parse(body);
    tree.tree = tree.tree
      .filter((entry) => entry.path === "docs/examples/org-airlock.yml")
      .map((entry) => ({ ...entry, path: "airlock/policy.yml" }));
    tree.tree.unshift({ path: "airlock", mode: "040000", type: "tree", sha: "0".repeat(40) });
    body = JSON.stringify(tree);
  }
  return new Response(body, { status: exchange.status, headers: { "content-type": "application/json" } });
}

test("the template's with: block audits the run's repository and stages the report", async () => {
  github = repositoryFetch(recording, { base, override: organizationPolicy });
  const run = await runAction({ inputs: TEMPLATE_INPUTS, name: "template" });
  assert.deepEqual(github.unexpected, []);
  const report = JSON.parse(run.findings);
  // The policy input reached the engine unchanged.
  assert.equal(report.policy.source, "wyrd-company/.github:airlock/policy.yml");
  assert.equal(report.repository.full_name, "wyrd-company/airlock");
  // The mask commands come first, then the report.
  assert.equal(run.log.split("\n")[0], `::add-mask::${RUN_TOKEN}`);
  assert.equal(run.outputs.outcome, report.outcome);
  assert.equal(run.outputs.complete, "true");
  assert.ok(["conformant", "nonconformant"].includes(report.outcome));
  assert.equal(run.status, report.outcome === "conformant" ? 0 : 1, run.log.slice(-2000));
  assert.equal(run.exported.AIRLOCK_OUTCOME, report.outcome);
  assert.equal(run.exported.AIRLOCK_COMPLETE, "true");
  assert.equal(run.exported.AIRLOCK_FINDINGS, run.outputs["findings-location"]);
  // The report, under the name the Worker reads.
  assert.equal(run.artifact.name, ARTIFACT);
  assert.equal(run.outputs.artifact, ARTIFACT);
  assert.deepEqual(Object.keys(run.artifactFiles), ["airlock-findings.json"]);
  assert.equal(run.artifactFiles["airlock-findings.json"], run.findings);
  assertNoToken(run);
});

test("text format writes the report for a person, and the artifact holds it", async () => {
  github = repositoryFetch(recording, { base, override: organizationPolicy });
  const run = await runAction({ inputs: { ...TEMPLATE_INPUTS, format: "text" }, name: "text" });
  assert.equal(run.outputs.complete, "true");
  assert.match(run.outputs["findings-location"], /\.txt$/);
  assert.deepEqual(Object.keys(run.artifactFiles), ["airlock-findings.txt"]);
  assert.throws(() => JSON.parse(run.findings));
  assertNoToken(run);
});

test("a job with a write permission is refused, and the refusal is the report", async () => {
  github = repositoryFetch(recording, {
    base,
    workflow: workflowDeclaring(["contents: read", "pull-requests: write"]),
  });
  const run = await runAction({ inputs: TEMPLATE_INPUTS, name: "write" });
  assert.equal(run.status, 1);
  assert.equal(run.outputs.outcome, "incomplete");
  assert.equal(run.outputs.complete, "false");
  const document = JSON.parse(run.findings);
  assert.equal(document.outcome, "incomplete");
  assert.equal(document.mode, "repository");
  assert.match(document.message, /write_permission/);
  assert.match(document.message, /pull-requests=write/);
  assert.deepEqual(
    github.requests.map((sent) => sent.path.split("?")[0]),
    ["/installation/repositories", "/repos/wyrd-company/airlock/contents/.github/workflows/audit.yml"],
    "nothing but the token's reach and the workflow file was read",
  );
  assert.equal(run.artifact.name, ARTIFACT);
  assertNoToken(run);
});

test("a token outside Actions is refused before any request", async () => {
  github = repositoryFetch(recording, { base });
  const run = await runAction({
    inputs: TEMPLATE_INPUTS,
    variables: actionsVariables({ GITHUB_ACTIONS: undefined }),
    name: "outside",
  });
  assert.equal(run.status, 1);
  assert.equal(run.outputs.outcome, "incomplete");
  assert.match(JSON.parse(run.findings).message, /outside_actions/);
  assert.equal(github.requests.length, 0);
  assertNoToken(run);
});

test("central mode is refused, and the refusal names the Worker's scheduled audit", async () => {
  github = repositoryFetch(recording, { base });
  // fail-on-incomplete: false does not rescue a mode other than repository.
  for (const failOnIncomplete of ["true", "false"]) {
    const run = await runAction({
      inputs: { ...TEMPLATE_INPUTS, mode: "central", "fail-on-incomplete": failOnIncomplete },
      name: `central-${failOnIncomplete}`,
    });
    assert.equal(run.status, 1);
    assert.equal(run.outputs.outcome, "incomplete");
    const document = JSON.parse(run.findings);
    assert.equal(document.mode, "central");
    assert.match(document.message, /Airlock Worker's scheduled central audit/);
    assert.match(run.log, /::error::central mode is no longer part of this action/);
    assertNoToken(run);
  }
  assert.equal(github.requests.length, 0);
});

test("any mode other than repository is refused before any request", async () => {
  github = repositoryFetch(recording, { base });
  for (const mode of ["organization", "Repository", "repository central"]) {
    const run = await runAction({ inputs: { ...TEMPLATE_INPUTS, mode, "fail-on-incomplete": "false" }, name: "mode" });
    assert.equal(run.status, 1, mode);
    assert.equal(run.outputs.outcome, "incomplete");
    assert.match(JSON.parse(run.findings).message, /mode must be 'repository'/);
  }
  assert.equal(github.requests.length, 0);
});

test("fail-on-incomplete: false lets a refused repository-mode audit succeed, still reporting it", async () => {
  github = repositoryFetch(recording, { base });
  const run = await runAction({
    inputs: { ...TEMPLATE_INPUTS, "fail-on-incomplete": "false" },
    variables: actionsVariables({ GITHUB_ACTIONS: undefined }),
    name: "forgiven",
  });
  assert.equal(run.status, 0);
  assert.equal(run.outputs.outcome, "incomplete");
  assert.equal(run.outputs.complete, "false");
  assert.equal(run.artifact.name, ARTIFACT);
});

test("invalid inputs are incomplete documents in the requested shape", async () => {
  github = repositoryFetch(recording, { base });
  for (const [inputs, pattern] of [
    [{ format: "xml" }, /format must be/],
    [{ "fail-on-incomplete": "maybe" }, /fail-on-incomplete must be/],
    [{ token: "" }, /needs the token input/],
    [{ policy: "./policy.yml" }, /owner\/repo:path/],
  ]) {
    const run = await runAction({ inputs: { ...TEMPLATE_INPUTS, ...inputs }, name: "invalid" });
    assert.equal(run.status, 1, JSON.stringify(inputs));
    assert.equal(run.outputs.outcome, "incomplete");
    assert.match(run.findings, pattern);
    assertNoToken(run);
  }
});

test("an installation token other than the run's own is refused", async () => {
  const other = "ghs_SYNTHETICotherTOKEN0123456789abcdef";
  github = repositoryFetch(recording, { base, bearer: other });
  const run = await runAction({ inputs: { ...TEMPLATE_INPUTS, token: other }, name: "foreign" });
  assert.equal(run.status, 1);
  assert.match(JSON.parse(run.findings).message, /foreign_installation_token/);
  assert.equal(github.requests.length, 0);
  assertNoToken(run, [RUN_TOKEN, other]);
});

test("no output carries a token when every GitHub answer echoes it", async () => {
  const echo = () =>
    new Response(JSON.stringify({ message: `Bad credentials ${RUN_TOKEN}`, documentation_url: RUN_TOKEN }), {
      status: 403,
      headers: { "content-type": "application/json", "x-github-request-id": RUN_TOKEN },
    });
  for (const failAt of ["/contents/", "/repos/wyrd-company/.github/", "/rules/branches", "/topics"]) {
    github = repositoryFetch(recording, {
      base,
      override: (path) => (path.includes(failAt) ? echo() : organizationPolicy(path)),
    });
    const run = await runAction({ inputs: TEMPLATE_INPUTS, name: "echo" });
    assert.ok(run.findings, failAt);
    assertNoToken(run);
  }
});

test("a forged pair is refused: the caller cannot supply the run's token", async () => {
  // Another App's installation token, which the caller holds, passed as
  // `token` and offered as the run's token in every way a caller could.
  // action.yml sets AIRLOCK_RUN_TOKEN to github.token in its step's own env,
  // and the action reads the run's token from there alone; a run-token input
  // no longer exists. The CI job "Action: a forged run token is refused"
  // proves the step env wins over the caller's job and step env.
  const forged = "ghs_999999_eyJhbGciOiJSUzI1NiJ9.eyJGT1JHRUQiOiJvdGhlci1hcHAifQ.Rk9SR0VE-c2lnbmF0dXJl_MARKER7";
  github = repositoryFetch(recording, { base, bearer: forged });
  const run = await runAction({
    inputs: { ...TEMPLATE_INPUTS, token: forged, "run-token": forged },
    env: { "INPUT_RUN-TOKEN": forged },
    name: "forged",
  });
  assert.equal(run.status, 1);
  assert.equal(run.outputs.outcome, "incomplete");
  assert.match(JSON.parse(run.findings).message, /foreign_installation_token/);
  assert.equal(github.requests.length, 0, "the forged token was never sent");
  assertNoToken(run, [RUN_TOKEN, forged]);
});

test("the forged pair is refused even when the environment defences were bypassed", async () => {
  // Caller code rewrote AIRLOCK_RUN_TOKEN to the forged token too, so the
  // two sides agree: the engine's form check refuses it before any request.
  const forged = "ghs_999999_eyJhbGciOiJSUzI1NiJ9.eyJGT1JHRUQiOiJvdGhlci1hcHAifQ.Rk9SR0VE-c2lnbmF0dXJl_MARKER7";
  github = repositoryFetch(recording, { base, bearer: forged });
  const run = await runAction({
    inputs: { ...TEMPLATE_INPUTS, token: forged },
    env: { AIRLOCK_RUN_TOKEN: forged },
    name: "bypassed",
  });
  assert.equal(run.status, 1);
  assert.equal(run.outputs.outcome, "incomplete");
  const message = JSON.parse(run.findings).message;
  assert.match(message, /not_actions_token/);
  assert.match(message, /changed its token format/);
  assert.equal(github.requests.length, 0, "the forged token was never sent");
  assertNoToken(run, [RUN_TOKEN, forged]);
});

test("each job, matrix leg and attempt stages under its own artifact name", async () => {
  github = repositoryFetch(recording, { base });
  const names = [];
  for (const [env, expected] of [
    [{ AIRLOCK_JOB_CHECK_RUN_ID: "100" }, "airlock-findings-100"],
    // A re-run of the job is a new check run.
    [{ AIRLOCK_JOB_CHECK_RUN_ID: "101", GITHUB_RUN_ATTEMPT: "2" }, "airlock-findings-101"],
    // A runner without job.check_run_id falls back to the job and attempt.
    [{ AIRLOCK_JOB_CHECK_RUN_ID: "", GITHUB_RUN_ATTEMPT: "3" }, "airlock-findings-audit-3"],
  ]) {
    const run = await runAction({
      inputs: TEMPLATE_INPUTS,
      variables: actionsVariables({ GITHUB_ACTIONS: undefined }),
      env,
      name: "names",
    });
    assert.equal(run.artifact.name, expected);
    assert.equal(run.outputs.artifact, expected);
    names.push(run.artifact.name);
  }
  assert.equal(new Set(names).size, names.length);
});

/** Every name action/step.sh may hand Node, and nothing else. */
const STEP_ALLOWLIST = [
  "PATH", "HOME", "RUNNER_TEMP",
  "GITHUB_ACTIONS", "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_ACTION", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
  "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_JOB",
  "GITHUB_API_URL",
  "INPUT_MODE", "INPUT_REPOSITORY", "INPUT_POLICY", "INPUT_REF", "INPUT_FORMAT", "INPUT_FAIL_ON_INCOMPLETE",
  "AIRLOCK_JOB_CHECK_RUN_ID", "AIRLOCK_CREDENTIALS_ON_STDIN",
];

test("the audit step hands Node only its allowlist, and the credentials only on stdin", async () => {
  // Every route a variable in the caller's job env could take into Node: code
  // loaded at start, a proxy for GitHub's answers with TLS checks off, extra
  // CAs, a preload, and a bash function that would shadow a builtin.
  const marker = join(scratch, "forge-marker");
  const hostile = {
    // Single quotes: Node reads double quotes in NODE_OPTIONS as its own quoting.
    NODE_OPTIONS: `--import=data:text/javascript,import{writeFileSync}from'node:fs';writeFileSync('${marker}','');process.env.AIRLOCK_RUN_TOKEN='forged'`,
    NODE_USE_ENV_PROXY: "1",
    HTTPS_PROXY: "http://127.0.0.1:9",
    HTTP_PROXY: "http://127.0.0.1:9",
    https_proxy: "http://127.0.0.1:9",
    http_proxy: "http://127.0.0.1:9",
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
    NODE_EXTRA_CA_CERTS: "/nonexistent/ca.pem",
    NODE_USE_SYSTEM_CA: "1",
    SSL_CERT_FILE: "/nonexistent/cert.pem",
    SSL_CERT_DIR: "/nonexistent",
    NODE_PATH: "/nonexistent",
    UNRELATED_CALLER_VARIABLE: "x",
    // printf is a regular builtin, which a bash function would shadow; dash
    // imports no functions.
    "BASH_FUNC_printf%%": `() { echo "caller saw $*" > '${marker}-printf'; }`,
  };
  // The forge is live: an ordinary Node given the same environment runs the
  // caller's code and cannot reach the fake GitHub past the dead proxy.
  const ordinary = spawnSync(
    process.execPath,
    ["-e", `fetch(${JSON.stringify(base)}).then(() => process.exit(0), () => process.exit(3))`],
    { env: { PATH: process.env.PATH, ...hostile } },
  );
  assert.equal(existsSync(marker), true, "the caller's NODE_OPTIONS runs in an ordinary Node");
  assert.equal(ordinary.status, 3, "an ordinary Node's fetch goes to the dead proxy");
  rmSync(marker);

  github = repositoryFetch(recording, { base, override: organizationPolicy });
  const run = await runAction({ inputs: TEMPLATE_INPUTS, env: hostile, name: "step", viaStep: true });
  // The audit reached the fake GitHub directly, not the dead proxy.
  assert.deepEqual(github.unexpected, []);
  assert.equal(run.outputs.complete, "true", run.log.slice(-1500));
  assert.ok(["conformant", "nonconformant"].includes(run.outputs.outcome));
  assert.equal(existsSync(marker), false, "the caller's NODE_OPTIONS never ran");
  assert.equal(existsSync(`${marker}-printf`), false, "no caller function ran");
  // PWD is set by the stand-in's own shell, after env -i started it.
  const names = run.nodeEnv
    .split("\n")
    .filter(Boolean)
    .map((line) => line.split("=")[0])
    .filter((name) => name !== "PWD");
  assert.deepEqual(names.filter((name) => !STEP_ALLOWLIST.includes(name)), [], "only allowlisted names reach Node");
  assert.match(run.nodeEnv, new RegExp(`^PATH=${run.directory}/node-bin:/usr/bin:/bin$`, "m"));
  assert.ok(!run.nodeEnv.includes(RUN_TOKEN), "no credential is in Node's environment");
  assertNoToken(run);
});

test("through the step, a forged pair is still refused before any request", async () => {
  const forged = "ghs_999999_eyJhbGciOiJSUzI1NiJ9.eyJGT1JHRUQiOiJvdGhlci1hcHAifQ.Rk9SR0VE-c2lnbmF0dXJl_MARKER7";
  github = repositoryFetch(recording, { base, bearer: forged });
  const run = await runAction({
    inputs: { ...TEMPLATE_INPUTS, token: forged },
    env: { AIRLOCK_RUN_TOKEN: forged },
    name: "step-forged",
    viaStep: true,
  });
  assert.equal(run.status, 1);
  assert.match(JSON.parse(run.findings).message, /not_actions_token/);
  assert.equal(github.requests.length, 0);
  assertNoToken(run, [RUN_TOKEN, forged]);
});

test("the step refuses a Node that is not the pinned one", async () => {
  github = repositoryFetch(recording, { base });
  const run = await runAction({
    inputs: TEMPLATE_INPUTS,
    env: { AIRLOCK_NODE_VERSION: "24.0.0" },
    name: "step-version",
    viaStep: true,
  });
  assert.notEqual(run.status, 0);
  assert.match(run.log, /not the pinned v24\.0\.0/);
  assert.equal(github.requests.length, 0);
});

test("the step refuses a Node whose SHA-256 is not the official build's", async () => {
  github = repositoryFetch(recording, { base });
  const run = await runAction({ inputs: TEMPLATE_INPUTS, name: "step-digest", viaStep: "real" });
  assert.notEqual(run.status, 0);
  assert.match(run.log, /is not Node's official v24\.22\.3 build/);
  assert.equal(github.requests.length, 0);
  assert.equal(run.nodeEnv, undefined, "the stand-in never ran");
});

test("the step refuses, before any command a function could shadow, a shell that is not dash", async () => {
  // bash as sh still imports BASH_FUNC_* functions, which would shadow
  // printf while it holds the credentials. The step exits 70 and runs
  // nothing.
  const marker = join(scratch, "bash-function-marker");
  const imported = { "BASH_FUNC_printf%%": `() { echo "caller saw $*" > '${marker}'; }` };
  // The forge is live: bash as sh runs the imported function for printf.
  spawnSync("/bin/bash", ["-c", "printf x"], { env: { PATH: process.env.PATH, ...imported }, argv0: "sh" });
  assert.equal(existsSync(marker), true, "bash as sh runs an imported printf");
  rmSync(marker);
  github = repositoryFetch(recording, { base });
  const run = await runAction({
    inputs: TEMPLATE_INPUTS,
    env: imported,
    name: "step-bash",
    viaStep: true,
    shell: "/bin/bash",
  });
  assert.equal(run.status, 70);
  assert.equal(existsSync(marker), false, "the caller's function never ran");
  assert.equal(run.nodeEnv, undefined);
  assert.equal(github.requests.length, 0);
});

test("the step refuses a runner that is not Linux, and an unknown architecture", async () => {
  github = repositoryFetch(recording, { base });
  const macos = await runAction({ inputs: TEMPLATE_INPUTS, env: { AIRLOCK_RUNNER_OS: "macOS" }, name: "step-os", viaStep: true });
  assert.equal(macos.status, 70);
  const arch = await runAction({ inputs: TEMPLATE_INPUTS, env: { AIRLOCK_NODE_ARCH: "x86" }, name: "step-arch", viaStep: true });
  assert.notEqual(arch.status, 0);
  assert.match(arch.log, /x64 or arm64 Linux runners only/);
  assert.equal(github.requests.length, 0);
});
