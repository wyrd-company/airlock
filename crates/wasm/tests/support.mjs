// Shared parts of the module's tests: loading the built module, replaying a
// recording, and fake Entra ID, Key Vault and GitHub.
//
// Every credential below is a synthetic marker, so a test can show that no
// output carries one.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = resolve(here, "../../..");

/** Load the module wasm-bindgen wrote to AIRLOCK_WASM_PKG. */
export async function loadModule() {
  const pkg = resolve(repositoryRoot, process.env.AIRLOCK_WASM_PKG ?? "target/wasm-pkg");
  const module = await import(resolve(pkg, "airlock.js"));
  module.initSync({ module: readFileSync(resolve(pkg, "airlock_bg.wasm")) });
  return module;
}

export function readRecording(name) {
  return JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
}

export const SECRETS = {
  clientSecret: "client-secret-MARKER1",
  vaultToken: "vault-access-token-MARKER2",
  signature: Buffer.from("rs256-signature-bytes-MARKER3").toString("base64url"),
  minted: "ghs_mintedMARKER4",
};

/** Fail when `text` carries any secret marker. */
export function assertNoSecret(assert, text, label = "output") {
  for (const [name, secret] of Object.entries(SECRETS)) {
    assert.ok(!String(text).includes(secret), `${label} carries ${name}`);
  }
}

export const TENANT = "11111111-2222-3333-4444-555555555555";
export const CLIENT = "66666666-7777-8888-9999-000000000000";
export const SAFE_APP_ID = 4409712;
export const INSTALLATION = 77;
export const GITHUB = "https://api.github.test";
export const LOGIN = "https://login.test";
export const VAULT = "https://vault.test";

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** The request as a fake sees it. */
async function received(url, init) {
  const headers = Object.fromEntries(init.headers ?? []);
  const body = init.body ? Buffer.from(init.body).toString("utf8") : "";
  return { method: init.method, url: new URL(url), headers, body, redirect: init.redirect };
}

/**
 * A recording replayed as a fetch: each request must match a recorded one
 * by method and path, and carry `Bearer <bearer>`.
 */
export function replay(recording, { base = "https://api.github.com", bearer = recording.token } = {}) {
  const unexpected = [];
  const served = [];
  const answer = (request) => {
    const path = request.url.pathname + request.url.search;
    const exchange = recording.exchanges.find(
      (candidate) => candidate.method === request.method && candidate.path === path,
    );
    if (!exchange || request.headers.authorization !== `Bearer ${bearer}`) {
      unexpected.push(`${request.method} ${path}`);
      return json(404, { message: "Not Found" });
    }
    served.push(`${request.method} ${path}`);
    const headers = exchange.headers.map(([name, value]) => [
      name,
      name === "link" ? value.replaceAll("https://api.github.com", base) : value,
    ]);
    return new Response(exchange.body, { status: exchange.status, headers });
  };
  return { answer, unexpected, served };
}

/** The installation as GitHub answers it. */
export function installation(selection = "all") {
  return {
    id: INSTALLATION,
    app_id: SAFE_APP_ID,
    app_slug: "airlock-safe",
    account: { login: "wyrd-company", type: "Organization" },
    repository_selection: selection,
    permissions: { metadata: "read", contents: "read" },
  };
}

/**
 * Fake Entra ID, Key Vault and GitHub, as a fetch. `overrides` maps a route
 * (`METHOD /path`) to a function that answers it instead. `github` answers
 * any other GitHub request.
 */
export function fakeCentral({ overrides = {}, github } = {}) {
  const requests = [];
  const fetch = async (url, init) => {
    const request = await received(url, init);
    requests.push(request);
    const route = `${request.method} ${request.url.origin}${request.url.pathname}`;
    if (overrides[route]) return overrides[route](request);
    switch (route) {
      case `POST ${LOGIN}/${TENANT}/oauth2/v2.0/token`:
        return json(200, { token_type: "Bearer", access_token: SECRETS.vaultToken });
      case `POST ${VAULT}/keys/airlock-safe//sign`:
        if (request.headers.authorization !== `Bearer ${SECRETS.vaultToken}`) return json(401, {});
        return json(200, { kid: `${VAULT}/keys/airlock-safe/1`, value: SECRETS.signature });
      case `GET ${GITHUB}/app`:
        return json(200, {
          id: SAFE_APP_ID,
          slug: "airlock-safe",
          permissions: { metadata: "read", contents: "read" },
        });
      case `GET ${GITHUB}/orgs/wyrd-company/installation`:
        return json(200, installation());
      case `POST ${GITHUB}/app/installations/${INSTALLATION}/access_tokens`:
        return json(201, {
          token: SECRETS.minted,
          expires_at: "2027-01-15T12:00:00Z",
          permissions: { metadata: "read", contents: "read" },
        });
      case `DELETE ${GITHUB}/installation/token`:
        return new Response(null, { status: 204 });
      default:
        if (github && request.url.origin === GITHUB) return github(request);
        return json(404, { message: "Not Found" });
    }
  };
  const to = (method, path) =>
    requests.filter((request) => request.method === method && request.url.href.startsWith(path));
  return { fetch, requests, to };
}

/** The central request the module takes. */
export function centralRequest(credential = { kind: "client-secret", value: SECRETS.clientSecret }) {
  return JSON.stringify({
    owner: "wyrd-company",
    appId: String(SAFE_APP_ID),
    keyName: "airlock-safe",
    installationRepositories: "wyrd-company/*",
    vaultUrl: VAULT,
    azureTenantId: TENANT,
    azureClientId: CLIENT,
    credential,
    githubApi: GITHUB,
    azureLogin: LOGIN,
  });
}

/** A clock the test moves, and a sleep that moves it instead of waiting. */
export function fakeClock(start = 1_800_000_000_000) {
  const clock = { now: start, sleeps: [] };
  clock.read = () => clock.now;
  clock.sleep = async (ms) => {
    clock.sleeps.push(ms);
    clock.now += ms;
  };
  return clock;
}

// Repository mode: the run's own token, judged by the job that holds it.

/** The run's own token, a synthetic marker shaped like an installation token. */
export const RUN_TOKEN = "ghs_SYNTHETICrunTOKEN0123456789abcdef";
export const WORKFLOW_SHA = "aa31121c5ead759d07c21915004de8c52b7597a7";
export const WORKFLOW_PATH = ".github/workflows/audit.yml";

/** The variables GitHub Actions sets for a run of `audit` in audit.yml. */
export function actionsVariables(overrides = {}) {
  const variables = {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "wyrd-company/airlock",
    GITHUB_WORKFLOW_REF: `wyrd-company/airlock/${WORKFLOW_PATH}@refs/heads/main`,
    GITHUB_WORKFLOW_SHA: WORKFLOW_SHA,
    GITHUB_JOB: "audit",
    ...overrides,
  };
  for (const [name, value] of Object.entries(variables)) if (value === undefined) delete variables[name];
  return variables;
}

/** A workflow whose `audit` job declares `permissions`, as YAML lines. */
export function workflowDeclaring(permissions = ["contents: read", "actions: read", "attestations: read"]) {
  return [
    "permissions: {}",
    "jobs:",
    "  audit:",
    "    runs-on: ubuntu-latest",
    "    permissions:",
    ...permissions.map((line) => `      ${line}`),
    "    steps: []",
    "",
  ].join("\n");
}

/**
 * The recording, answered for `bearer`, with the workflow file GitHub ran
 * served at the run's commit. `override(path)` may answer first.
 */
export function repositoryFetch(recording, {
  base,
  bearer = RUN_TOKEN,
  workflow = workflowDeclaring(),
  override = () => undefined,
} = {}) {
  const recorded = replay(recording, { base, bearer });
  const requests = [];
  const fetch = async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    const headers = Object.fromEntries(init.headers ?? []);
    requests.push({ method: init.method, path, headers });
    const answered = override(path, headers);
    if (answered) return answered;
    if (path === `/repos/wyrd-company/airlock/contents/${WORKFLOW_PATH}?ref=${WORKFLOW_SHA}`) {
      if (headers.authorization !== `Bearer ${bearer}`) return json(401, { message: "Bad credentials" });
      return json(200, {
        type: "file",
        encoding: "base64",
        content: Buffer.from(workflow).toString("base64"),
      });
    }
    return recorded.answer({ method: init.method, url: parsed, headers });
  };
  return { fetch, requests, unexpected: recorded.unexpected };
}
