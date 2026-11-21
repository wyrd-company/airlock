// Central sign-in in the WebAssembly module, against fake Entra ID, Key
// Vault and GitHub. The host is the shipped fetch host, over a fake fetch.

import assert from "node:assert/strict";
import { before, test } from "node:test";

import { fetchHost } from "../js/host.mjs";
import {
  CLIENT,
  GITHUB,
  INSTALLATION,
  LOGIN,
  SAFE_APP_ID,
  SECRETS,
  TENANT,
  VAULT,
  assertNoSecret,
  centralRequest,
  fakeCentral,
  fakeClock,
  installation,
  loadModule,
  readRecording,
  replay,
} from "./support.mjs";

let airlock;
before(async () => {
  airlock = await loadModule();
});

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Sign in, expecting a refusal, and return it. */
async function refused(fake, request = centralRequest()) {
  const error = await airlock.CentralSession.signIn(fetchHost({ fetch: fake.fetch }), request).then(
    () => assert.fail("the sign-in was refused"),
    (error) => error,
  );
  assert.equal(error.name, "AirlockError");
  assertNoSecret(assert, `${error.message} ${JSON.stringify(error)}`, "the refusal");
  return error;
}

test("signs in as Airlock Safe with a client secret, in the order of the sign-in", async () => {
  const fake = fakeCentral();
  const clock = fakeClock();
  const session = await airlock.CentralSession.signIn(
    fetchHost({ fetch: fake.fetch, now: clock.read, sleep: clock.sleep }),
    centralRequest(),
  );
  try {
    const grant = JSON.parse(session.grant());
    assert.deepEqual(grant, {
      appSlug: "airlock-safe",
      appId: SAFE_APP_ID,
      installationId: INSTALLATION,
      permissions: ["contents=read", "metadata=read"],
      expiresAt: "2027-01-15T12:00:00Z",
    });
    assertNoSecret(assert, session.grant(), "the grant");

    assert.deepEqual(
      fake.requests.map((request) => `${request.method} ${request.url.origin}${request.url.pathname}`),
      [
        `POST ${LOGIN}/${TENANT}/oauth2/v2.0/token`,
        `POST ${VAULT}/keys/airlock-safe//sign`,
        `GET ${GITHUB}/app`,
        `GET ${GITHUB}/orgs/wyrd-company/installation`,
        `POST ${GITHUB}/app/installations/${INSTALLATION}/access_tokens`,
      ],
    );
    for (const request of fake.requests) {
      // Every request carries a credential, so none may follow a redirect.
      assert.equal(request.redirect, "manual", `${request.method} ${request.url}`);
    }

    // Entra ID got the client secret as a form, and no assertion.
    const form = new URLSearchParams(fake.requests[0].body);
    assert.equal(form.get("client_id"), CLIENT);
    assert.equal(form.get("client_secret"), SECRETS.clientSecret);
    assert.equal(form.get("scope"), "https://vault.azure.net/.default");
    assert.equal(form.get("grant_type"), "client_credentials");
    assert.equal(form.get("client_assertion"), null);

    // Key Vault signed the SHA-256 of the signing input GitHub was shown.
    const signed = JSON.parse(fake.requests[1].body);
    assert.equal(signed.alg, "RS256");
    const jwt = fake.requests[2].headers.authorization.replace(/^Bearer /, "");
    const [header, claims, signature] = jwt.split(".");
    assert.equal(signature, SECRETS.signature);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${header}.${claims}`));
    assert.equal(signed.value, Buffer.from(digest).toString("base64url"));

    // The token is dated by the host's clock: iat a minute back, exp nine
    // minutes on.
    const decoded = JSON.parse(Buffer.from(claims, "base64url").toString("utf8"));
    const now = clock.now / 1000;
    assert.deepEqual(decoded, { iat: now - 60, exp: now + 540, iss: String(SAFE_APP_ID) });

    await session.revoke();
    const revoke = fake.to("DELETE", `${GITHUB}/installation/token`);
    assert.equal(revoke.length, 1);
    assert.equal(revoke[0].headers.authorization, `Bearer ${SECRETS.minted}`);
  } finally {
    session.free();
  }
});

test("refuses a credential kind the module does not take, before any request", async () => {
  const fake = fakeCentral();
  for (const credential of [
    { kind: "github-oidc", value: "x" },
    // .github#26 settled on a client secret, so the module takes no other.
    { kind: "client-assertion", value: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln" },
  ]) {
    const error = await refused(fake, centralRequest(credential));
    assert.equal(error.kind, "inputs");
  }
  assert.equal(fake.requests.length, 0);
});

test("refuses another App before any request", async () => {
  const fake = fakeCentral();
  const request = JSON.parse(centralRequest());
  request.appId = "1";
  const error = await refused(fake, JSON.stringify(request));
  assert.equal(error.step, "inputs");
  assert.equal(fake.requests.length, 0);
});

test("stops at azure-sign-in when Entra ID refuses the secret, without repeating it", async () => {
  const fake = fakeCentral({
    overrides: {
      [`POST ${LOGIN}/${TENANT}/oauth2/v2.0/token`]: () =>
        json(401, {
          error: "invalid_client",
          error_description: `AADSTS7000215: Invalid client secret ${SECRETS.clientSecret}`,
          error_codes: [7000215],
        }),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "azure-sign-in");
  assert.equal(error.status, 401);
  assert.equal(error.code, "invalid_client, AADSTS7000215");
  assert.equal(fake.requests.length, 1);
});

test("stops at key-vault-sign when Key Vault refuses", async () => {
  const fake = fakeCentral({
    overrides: {
      [`POST ${VAULT}/keys/airlock-safe//sign`]: () =>
        json(403, { error: { code: "Forbidden", message: `caller ${SECRETS.vaultToken}` } }),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "key-vault-sign");
  assert.equal(error.status, 403);
  assert.equal(error.code, "Forbidden");
});

test("stops at app-identity when GET /app lists a permission that is not read", async () => {
  const fake = fakeCentral({
    overrides: {
      [`GET ${GITHUB}/app`]: () =>
        json(200, {
          id: SAFE_APP_ID,
          slug: "airlock-safe",
          permissions: { metadata: "read", contents: "write" },
        }),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "app-identity");
  assert.match(error.message, /contents=write/);
  assert.equal(fake.to("POST", `${GITHUB}/app/installations`).length, 0);
});

test("stops at app-identity when the key signs for another App", async () => {
  const fake = fakeCentral({
    overrides: {
      [`GET ${GITHUB}/app`]: () =>
        json(200, { id: 1, slug: "another", permissions: { metadata: "read" } }),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "app-identity");
});

test("stops at installation-scope when the installation reaches selected repositories", async () => {
  const fake = fakeCentral({
    overrides: {
      [`GET ${GITHUB}/orgs/wyrd-company/installation`]: () => json(200, installation("selected")),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "installation-scope");
  assert.equal(fake.to("POST", `${GITHUB}/app/installations`).length, 0);
});

test("stops at token-request and revokes a minted token not shaped like a GitHub token", async () => {
  for (const token of ["ghs_s", 'ghs_quote"d_0123456789', "ghs_per%2fcent_0123456789"]) {
    const fake = fakeCentral({
      overrides: {
        [`POST ${GITHUB}/app/installations/${INSTALLATION}/access_tokens`]: () =>
          json(201, { token, permissions: { metadata: "read" } }),
      },
    });
    const error = await refused(fake);
    assert.equal(error.step, "token-request", token);
    assert.match(error.message, /not shaped like a GitHub token/);
    assert.ok(!error.message.includes(token));
    assert.equal(fake.to("DELETE", `${GITHUB}/installation/token`).length, 1, token);
  }
});

test("stops at token-request and revokes a minted token that can write", async () => {
  const fake = fakeCentral({
    overrides: {
      [`POST ${GITHUB}/app/installations/${INSTALLATION}/access_tokens`]: () =>
        json(201, {
          token: SECRETS.minted,
          permissions: { metadata: "read", contents: "write" },
        }),
    },
  });
  const error = await refused(fake);
  assert.equal(error.step, "token-request");
  assert.match(error.message, /revoked/);
  const revoke = fake.to("DELETE", `${GITHUB}/installation/token`);
  assert.equal(revoke.length, 1);
  assert.equal(revoke[0].headers.authorization, `Bearer ${SECRETS.minted}`);
});

test("a signed-in session audits a repository with Safe's token, and no output carries a secret", async () => {
  const recording = readRecording("audit-airlock.json");
  const github = replay(recording, { base: GITHUB, bearer: SECRETS.minted });
  const fake = fakeCentral({ github: github.answer });
  const session = await airlock.CentralSession.signIn(fetchHost({ fetch: fake.fetch }), centralRequest());
  try {
    const raw = await session.auditRepository("airlock", recording.request.policy);
    assertNoSecret(assert, raw, "the report");
    const report = JSON.parse(raw);
    assert.equal(report.repository.full_name ?? `${report.repository.owner}/${report.repository.name}`, "wyrd-company/airlock");
    assert.ok(report.findings.length > 0);
    assert.deepEqual(github.unexpected, []);
    for (const request of fake.requests.filter((request) => request.url.origin === GITHUB && request.url.pathname.startsWith("/repos/"))) {
      assert.equal(request.headers.authorization, `Bearer ${SECRETS.minted}`);
    }
  } finally {
    await session.revoke();
    session.free();
  }
});
