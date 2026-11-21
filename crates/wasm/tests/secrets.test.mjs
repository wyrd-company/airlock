// No output of the module carries a credential. Each error path the module
// can reach is fed a distinctive synthetic token. The fakes echo the token in
// every place a server or host could: a message, a body, a rejection. Every
// string that leaves the module must still be free of it.

import assert from "node:assert/strict";
import { before, test } from "node:test";

import { fetchHost } from "../js/host.mjs";
import {
  GITHUB,
  SECRETS,
  centralRequest,
  fakeCentral,
  loadModule,
  readRecording,
  replay,
} from "./support.mjs";

const BASE = "https://api.github.test";
const TOKEN = "ghu_SYNTHETICtoken0123456789abcdef";
const REPOSITORY = "/repos/wyrd-company/airlock";

let airlock;
let recording;
before(async () => {
  airlock = await loadModule();
  recording = readRecording("audit-airlock.json");
});

function request(token = TOKEN) {
  return JSON.stringify({ token, ...recording.request, githubApi: BASE });
}

function echo(status, secret = TOKEN) {
  return new Response(
    JSON.stringify({
      message: `Bad credentials: Bearer ${secret}`,
      documentation_url: `https://docs.github.com/?token=${secret}`,
    }),
    {
      status,
      headers: {
        "content-type": "application/json",
        "x-accepted-github-permissions": `contents=read ${secret}`,
        "x-github-request-id": secret,
      },
    },
  );
}

/** The recording for TOKEN, with `override(path)` able to answer first. */
function hostWith(override = () => undefined, bearer = TOKEN) {
  const recorded = replay(recording, { base: BASE, bearer });
  const fetch = async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    return (
      override(path) ??
      recorded.answer({ method: init.method, url: parsed, headers: Object.fromEntries(init.headers) })
    );
  };
  return fetchHost({ fetch });
}

/** Every string an error exposes: message, string form, and own props. */
function everything(value) {
  if (value instanceof Error || (value && typeof value === "object")) {
    const props = Object.fromEntries(
      Object.getOwnPropertyNames(value).map((name) => [name, String(value[name])]),
    );
    return `${String(value)} ${JSON.stringify(props)}`;
  }
  return String(value);
}

async function outcome(promise) {
  try {
    return { text: await promise, failed: false };
  } catch (error) {
    return { text: everything(error), failed: true, error };
  }
}

function assertClean(text, secrets = [TOKEN]) {
  for (const secret of secrets) {
    assert.ok(!text.includes(secret), `the output carries ${secret}: ${text.slice(0, 400)}`);
  }
}

const cases = [
  ["verification answered 401 with the token in its message", (path) =>
    path.startsWith("/user/installations") ? echo(401) : undefined],
  ["verification answered 403 with the token in every header", (path) =>
    path.startsWith("/user/installations") ? echo(403) : undefined],
  ["verification answered with a body that is not JSON", (path) =>
    path.startsWith("/user/installations") ? new Response(`not json ${TOKEN}`, { status: 200 }) : undefined],
  ["verification answered with a malformed installation", (path) =>
    path.startsWith("/user/installations")
      ? new Response(JSON.stringify({ installations: [{ id: TOKEN }] }), { status: 200 })
      : undefined],
  ["the policy read answered 404 with the token in its message", (path) =>
    path.startsWith("/repos/wyrd-company/airlock/commits/aa31121") ? echo(404) : undefined],
  ["the repository read answered 500 with the token in its message", (path) =>
    path === REPOSITORY ? echo(500) : undefined],
  ["the repository read answered 404 with the token in its message", (path) =>
    path === REPOSITORY ? echo(404) : undefined],
  ["a rule's read answered 403 with the token in its message", (path) =>
    path.startsWith(`${REPOSITORY}/rulesets`) ? echo(403) : undefined],
  ["a rule's read answered a body that is not JSON", (path) =>
    path.startsWith(`${REPOSITORY}/topics`) ? new Response(`{${TOKEN}`, { status: 200 }) : undefined],
];

for (const [name, override] of cases) {
  test(`no output carries the token when ${name}`, async () => {
    const result = await outcome(airlock.audit(hostWith(override), request()));
    assertClean(result.text);
  });
}

test("no output carries the token when the host's fetch rejects with it", async () => {
  const host = {
    fetch: async () => {
      throw Object.assign(new Error(`connect failed for Bearer ${TOKEN}`), { name: `ConnectError ${TOKEN}` });
    },
    sleep: async () => {},
    now: () => 1_800_000_000_000,
  };
  const result = await outcome(airlock.audit(host, request()));
  assert.ok(result.failed);
  assertClean(result.text);
});

test("no output carries the token when the host's fetch answers something that is not a response", async () => {
  for (const answer of [TOKEN, { status: TOKEN }, { status: 200, headers: [[TOKEN, 1]], body: TOKEN }, null]) {
    const host = { fetch: async () => answer, sleep: async () => {}, now: () => 1_800_000_000_000 };
    const result = await outcome(airlock.audit(host, request()));
    assert.ok(result.failed);
    assertClean(result.text);
  }
});

test("no output carries the token when the host's clock throws it", async () => {
  const host = {
    fetch: async () => echo(500),
    sleep: async () => {},
    now: () => {
      throw new Error(`clock ${TOKEN}`);
    },
  };
  const result = await outcome(airlock.audit(host, request()));
  assert.ok(result.failed);
  assertClean(result.text);
});

test("no output carries the token when the request itself is malformed", async () => {
  for (const text of [
    `{"token":"${TOKEN}","owner":"wyrd-company"}`,
    `{"token":"${TOKEN}","owner":"wyrd-company","repo":"airlock","extra":"${TOKEN}"}`,
    `{"token":"${TOKEN}",`,
    JSON.stringify({ token: TOKEN, owner: "wyrd-company", repo: "airlock", policy: `not a policy ${TOKEN}` }),
    JSON.stringify({ token: TOKEN, owner: `bad owner ${TOKEN}`, repo: "airlock", githubApi: BASE }),
  ]) {
    const result = await outcome(airlock.audit(fetchHost({ fetch: async () => echo(500) }), text));
    assert.ok(result.failed, text);
    assertClean(result.text);
  }
});

test("a completed report carries no token even when a server echoes it", async () => {
  const result = await outcome(
    airlock.audit(
      hostWith((path) => (path.startsWith(`${REPOSITORY}/rules/branches`) ? echo(403) : undefined)),
      request(),
    ),
  );
  assert.equal(result.failed, false);
  assertClean(result.text);
  assert.ok(JSON.parse(result.text).findings.length > 0);
});

test("no central output carries the secret, the assertion or Safe's token when the services echo them", async () => {
  const everySecret = Object.values(SECRETS);
  const echoAll = (status) => echo(status, everySecret.join(" "));
  for (const route of [
    "POST https://login.test/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token",
    "POST https://vault.test/keys/airlock-safe//sign",
    `GET ${GITHUB}/app`,
    `GET ${GITHUB}/orgs/wyrd-company/installation`,
    `POST ${GITHUB}/app/installations/77/access_tokens`,
  ]) {
    const fake = fakeCentral({ overrides: { [route]: () => echoAll(401) } });
    const result = await outcome(airlock.CentralSession.signIn(fetchHost({ fetch: fake.fetch }), centralRequest()));
    assert.ok(result.failed, route);
    assertClean(result.text, everySecret);
  }

  // Signed in, a repository read that echoes Safe's token in an error.
  const github = replay(recording, { base: GITHUB, bearer: SECRETS.minted });
  const fake = fakeCentral({
    github: (request) =>
      request.url.pathname === REPOSITORY
        ? echoAll(500)
        : github.answer(request),
    overrides: { [`DELETE ${GITHUB}/installation/token`]: () => echoAll(500) },
  });
  const session = await airlock.CentralSession.signIn(fetchHost({ fetch: fake.fetch }), centralRequest());
  try {
    const audited = await outcome(session.auditRepository("airlock", recording.request.policy));
    assertClean(audited.text, everySecret);
    const all = await outcome(session.auditInstallation(recording.request.policy));
    assertClean(all.text, everySecret);
    // A host that rejects with Safe's token in its message, on every read.
    const signedIn = fetchHost({ fetch: fakeCentral().fetch });
    const rejecting = {
      ...signedIn,
      fetch: (req) =>
        req.headers.some(([name, value]) => name === "authorization" && value.includes(SECRETS.minted)) &&
        req.method === "GET"
          ? Promise.reject(new Error(`could not reach GitHub with Bearer ${SECRETS.minted}`))
          : signedIn.fetch(req),
    };
    const second = await airlock.CentralSession.signIn(rejecting, centralRequest());
    try {
      for (const run of [
        () => second.auditRepository("airlock", recording.request.policy),
        () => second.auditRepository("airlock"),
        () => second.auditInstallation(recording.request.policy),
      ]) {
        const result = await outcome(run());
        assertClean(result.text, everySecret);
      }
    } finally {
      second.free();
    }

    const revoked = await outcome(session.revoke());
    assert.ok(revoked.failed);
    assertClean(revoked.text, everySecret);
  } finally {
    session.free();
  }
});
