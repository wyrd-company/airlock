// Repository mode, as the JavaScript action runs it: the run's own token is
// admitted only inside Actions, for the run's own repository, when it is the
// run's own token and every permission its job declares is `read`.

import assert from "node:assert/strict";
import { before, test } from "node:test";

import { fetchHost } from "../js/host.mjs";
import {
  RUN_TOKEN,
  actionsVariables,
  loadModule,
  readRecording,
  repositoryFetch,
  workflowDeclaring,
} from "./support.mjs";

const BASE = "https://api.github.test";

let airlock;
let recording;
before(async () => {
  airlock = await loadModule();
  recording = readRecording("audit-airlock.json");
});

function request(overrides = {}) {
  return JSON.stringify({
    token: RUN_TOKEN,
    runToken: RUN_TOKEN,
    repository: "wyrd-company/airlock",
    policy: recording.request.policy,
    actions: actionsVariables(),
    githubApi: BASE,
    ...overrides,
  });
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("the audit was not refused");
}

test("the run's own token is admitted when every permission of its job is read", async () => {
  const fake = repositoryFetch(recording, { base: BASE });
  const result = JSON.parse(await airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request()));
  assert.deepEqual(fake.unexpected, []);
  assert.ok(["conformant", "nonconformant"].includes(result.outcome), result.outcome);
  assert.equal(result.complete, true);
  const report = JSON.parse(result.document);
  assert.equal(report.outcome, result.outcome);
  assert.equal(report.complete, result.complete);
  assert.ok(report.findings.length > 0);
  // The grant was read from the job, at the run's commit.
  assert.equal(fake.requests[0].path, `/repos/wyrd-company/airlock/contents/.github/workflows/audit.yml?ref=${actionsVariables().GITHUB_WORKFLOW_SHA}`);
  // Every request carried the run's token, and no request carried it anywhere else.
  for (const sent of fake.requests) {
    assert.equal(sent.headers.authorization, `Bearer ${RUN_TOKEN}`);
    assert.ok(!sent.path.includes(RUN_TOKEN));
  }
});

test("text format renders the same audit for a person", async () => {
  const fake = repositoryFetch(recording, { base: BASE });
  const result = JSON.parse(
    await airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ format: "text" })),
  );
  assert.equal(result.complete, true);
  assert.throws(() => JSON.parse(result.document));
  assert.match(result.document, /wyrd-company\/airlock/);
});

test("a job with a write permission is refused before anything else is read", async () => {
  for (const permission of ["contents: write", "issues: write", "id-token: write", "pull-requests: none"]) {
    const fake = repositoryFetch(recording, {
      base: BASE,
      workflow: workflowDeclaring(["actions: read", permission]),
    });
    const error = await refusal(airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request()));
    assert.equal(error.name, "AirlockError");
    assert.equal(error.kind, "refused", permission);
    assert.match(error.message, /write_permission/);
    assert.equal(fake.requests.length, 1, "only the workflow file was read");
  }
});

test("a job that declares no permissions is refused", async () => {
  const workflow = "jobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps: []\n";
  const fake = repositoryFetch(recording, { base: BASE, workflow });
  const error = await refusal(airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request()));
  assert.equal(error.kind, "refused");
  assert.match(error.message, /permissions_undeclared/);
});

test("a token outside Actions is refused before any request", async () => {
  for (const actions of [
    actionsVariables({ GITHUB_ACTIONS: undefined }),
    actionsVariables({ GITHUB_ACTIONS: "false" }),
    {},
  ]) {
    const fake = repositoryFetch(recording, { base: BASE });
    const error = await refusal(airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ actions })));
    assert.equal(error.kind, "refused");
    assert.match(error.message, /outside_actions/);
    assert.equal(fake.requests.length, 0);
  }
});

test("a run the variables do not describe is refused before any request", async () => {
  for (const actions of [
    actionsVariables({ GITHUB_JOB: undefined }),
    actionsVariables({ GITHUB_WORKFLOW_SHA: "main" }),
    actionsVariables({ GITHUB_WORKFLOW_REF: "someone-else/airlock/.github/workflows/audit.yml@refs/heads/main" }),
  ]) {
    const fake = repositoryFetch(recording, { base: BASE });
    const error = await refusal(airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ actions })));
    assert.equal(error.kind, "refused");
    assert.match(error.message, /run_undescribed/);
    assert.equal(fake.requests.length, 0);
  }
});

test("an installation token other than the run's own is refused before any request", async () => {
  const other = "ghs_SYNTHETICotherTOKEN0123456789abcdef";
  for (const runToken of [RUN_TOKEN, undefined, ""]) {
    const fake = repositoryFetch(recording, { base: BASE, bearer: other });
    const error = await refusal(
      airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ token: other, runToken })),
    );
    assert.equal(error.kind, "refused");
    assert.match(error.message, /foreign_installation_token|run_token_unbound/);
    assert.equal(fake.requests.length, 0);
    assert.ok(!error.message.includes(other) && !error.message.includes(RUN_TOKEN));
  }
});

test("repository mode audits the run's own repository only", async () => {
  const fake = repositoryFetch(recording, { base: BASE });
  const error = await refusal(
    airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ repository: "wyrd-company/other" })),
  );
  assert.equal(error.kind, "refused");
  assert.match(error.message, /foreign_repository/);
  assert.equal(fake.requests.length, 0);
});

test("inputs the module cannot use are refused before any request", async () => {
  for (const [overrides, pattern] of [
    [{ format: "xml" }, /format/],
    [{ repository: "airlock" }, /owner\/repo/],
    [{ repository: "wyrd-company/airlock/extra" }, /owner\/repo/],
    [{ token: "ghs_x" }, /not a GitHub token/],
    [{ mode: "central" }, /not valid/],
  ]) {
    const fake = repositoryFetch(recording, { base: BASE });
    const error = await refusal(airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request(overrides)));
    assert.equal(error.kind, "inputs", JSON.stringify(overrides));
    assert.match(error.message, pattern);
    assert.equal(fake.requests.length, 0);
  }
});

test("a local policy path is refused: the module reads no file system", async () => {
  const fake = repositoryFetch(recording, { base: BASE });
  const error = await refusal(
    airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request({ policy: "./policy.yml" })),
  );
  assert.equal(error.kind, "inputs");
  assert.match(error.message, /owner\/repo:path/);
});

test("no output carries either token when every server echoes them", async () => {
  const echo = () =>
    new Response(JSON.stringify({ message: `Bad credentials ${RUN_TOKEN}` }), {
      status: 403,
      headers: { "content-type": "application/json", "x-github-request-id": RUN_TOKEN },
    });
  // A failure at the workflow read, at the policy, and mid-audit.
  for (const failAt of ["/contents/", "/git/trees/aa31121", "/rules/branches"]) {
    const fake = repositoryFetch(recording, {
      base: BASE,
      override: (path) => (path.includes(failAt) ? echo() : undefined),
    });
    let text;
    try {
      text = await airlock.repositoryAudit(fetchHost({ fetch: fake.fetch }), request());
    } catch (error) {
      text = `${String(error)} ${JSON.stringify(Object.fromEntries(Object.getOwnPropertyNames(error).map((n) => [n, String(error[n])])))}`;
    }
    assert.ok(!text.includes(RUN_TOKEN), `${failAt}: ${text.slice(0, 300)}`);
  }
});
