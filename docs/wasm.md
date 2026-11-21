---
relationships:
  references:
    - ../crates/wasm/src/js.rs
    - ../crates/core/src/transport.rs
  implemented-by: ../crates/wasm/src/engine.rs
---

# The WebAssembly module

The Airlock engine is compiled to WebAssembly. The Airlock Worker and the
JavaScript action load the module. No Rust binary is published for them.
`crates/wasm` (`airlock-wasm`) builds it from `airlock-core` without the
core's `native` feature.

## What the module holds

Without `native`, the core keeps everything an API audit needs. It keeps
policy resolution, the rules and their checks, the findings report, central
sign-in and the central run. It drops what reads the local machine: the
working-tree modes (`align-files`, the mixed and local-only audits, local Git
reads), the skill emitter, and the native transport (reqwest and tokio). An
audit that asks for a working tree in the module is refused, not run against
the default branch.

The native build still has all of it. `cargo build --workspace` and
`cargo test --workspace` build the core with `native`, as before.

## Build

```sh
task wasm:install   # the wasm32 target, and the wasm-bindgen Cargo.lock locks
task wasm:build     # target/wasm-pkg/airlock.js, airlock.d.ts, airlock_bg.wasm
```

`task wasm:build` runs `scripts/build-wasm.sh`. It builds the `wasm-release`
profile (`opt-level = "z"`, LTO, stripped, abort on panic) and runs
`wasm-bindgen --target web`. Set `AIRLOCK_WASM_PKG` to write elsewhere. The
installed wasm-bindgen must be the version `Cargo.lock` locks, or the script
stops.

Load the module with `initSync({ module })`, passing the bytes of
`airlock_bg.wasm` under Node or the imported module in a Worker.

## The host interface

Every request the engine makes goes through one interface:
`airlock_core::transport::Transport`. The interface also supplies the wait
between rate-limited retries and the clock. The native build implements it
with `ReqwestTransport`. In the module, the host implements it by passing an
object to each entry point:

```ts
interface AirlockHost {
  fetch(request: AirlockRequest): Promise<AirlockResponse>;
  sleep(ms: number): Promise<void>;
  now(): number; // milliseconds since the Unix epoch
}

interface AirlockRequest {
  method: "GET" | "POST" | "DELETE";
  url: string;
  headers: [string, string][]; // lowercase names
  body?: Uint8Array;           // POST only
  redirect: "follow" | "manual";
  timeoutMs: number;
  maxResponseBytes: number;
}

interface AirlockResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array;
}
```

`airlock.d.ts` carries the same declarations. `crates/wasm/js/host.mjs`
exports `fetchHost()`, a host built on the platform's own `fetch`, for Node 22
or later and for Workers. Its parts can be replaced, which is how the tests
fake the network and the clock.

A host must keep to the following:

- **Send the request as built.** Send it with the given method, headers and
  body. Follow a redirect only for `redirect: "follow"`. With `manual`, the
  redirect is the answer. Every central request is `manual`, because each one
  carries a credential.
- **Answer with any status.** An HTTP error status is an answer, not a
  rejection. Reject only when no complete answer arrived. Give the rejection's
  `name` as `TimeoutError` when `timeoutMs` passed, `ConnectError` when no
  connection was made, or `TooLargeError` when the body passed
  `maxResponseBytes`. The engine reads a timeout as a budget failure and a
  connection failure as a transport failure. The engine also refuses a body
  over the limit when a host hands one back.
- **Never log a request.** The `authorization` header and the body carry
  credentials: a GitHub token, Entra ID's form, a Key Vault token or the App's
  JSON Web Token. The module keeps its own copies only in memory and
  overwrites them when it drops them. The copies the host's JavaScript makes
  are the host's to keep out of logs.
- **Keep the clock and the timer.** `now()` is read for the audit budget, the
  request timeout, a rate limit's reset and the App's JSON Web Token. It must
  return a number of milliseconds from 0 to 8.64e15, the range of a `Date`.
  It must never return less than it returned before. `fetchHost()` reads
  `performance.timeOrigin + performance.now()`, which does not step back when
  the system clock is set. `sleep()` is used only between rate-limited
  retries.
- **Expect untrusted-input checks.** The module checks every value the host
  returns: `now()` and the status, headers and body of a `fetch` answer. A
  value it cannot use is an error with the `Clock` or transport cause. Such a
  value can be a throw, NaN, a negative or out-of-range time, a step back, a
  `sleep()` that throws or rejects, or an answer of the wrong shape. None of
  these traps the module, and an instance that refused one keeps working. A
  plain value where a promise is expected is read as already resolved.
- **Provide `crypto.getRandomValues`.** A hash-map dependency of the schema
  validator seeds itself from it. Node and Workers both provide it.

`fetch`'s `Headers` joins a repeated response field with `, `. A host on
`fetch` therefore hands the engine one value where the native transport hands
it one per repetition.

### Time on `wasm32-unknown-unknown`

`std::time::Instant` and `SystemTime` panic on this target, and tokio's timer
cannot run there. No code in the module calls them. Every clock reading and
every wait goes through the host. The HTTP `Date` header is not parsed: the
report keeps it as text, in `repository.settings_observed_at`, after the
central run's shape check. `Retry-After` is read only as a number of seconds.
The HTTP-date form falls back to `x-ratelimit-reset`, or to one second, as in
the native build. `crates/wasm/tests/host.test.mjs` exercises each of these
paths.

## Entry points

The module's entry points are in `crates/wasm/src/engine.rs`. They are the
same for every target, so the native parity run executes the module's code.
`src/js.rs` exports them to JavaScript.

`audit(host, request)` audits one repository. `request` is JSON:
`{ token, owner, repo, policy?, githubApi? }`. The token is verified before
anything else is read, and admitted as the command line admits it. Repository
mode, which admits the run's own `GITHUB_TOKEN`, arrives with the JavaScript
action.

`CentralSession.signIn(host, request)` signs in as Airlock Safe through Azure
Key Vault, as central mode does (see the README's *Central mode*). Every
check of that mode holds:

- `GET /app` names Safe, with every permission `read`;
- the owner's installation has `repository_selection` `all` and passes the
  `installation-repositories` rule;
- the minted token lists only `read` permissions, or the module revokes it.

`request` is JSON:

```json
{
  "owner": "wyrd-company",
  "appId": "4409712",
  "keyName": "airlock-safe",
  "installationRepositories": "wyrd-company/*",
  "vaultUrl": "https://<vault>.vault.azure.net",
  "azureTenantId": "<tenant id>",
  "azureClientId": "<the host's Entra application>",
  "credential": { "kind": "client-secret", "value": "<from the secrets store>" }
}
```

The module has no GitHub Actions job to request an OpenID Connect token from.
The host proves itself to Entra ID with its own credential. `kind` is
`client-secret`, or `client-assertion` for a certificate credential: the host
signs the assertion and keeps the certificate's key. `githubApi` and
`azureLogin` override the service roots for tests.

The session holds Safe's installation token inside the module. No method
returns it, and every output passes through the session's redaction. A
session has these methods:

- `grant()` returns the verified credential as JSON.
- `auditRepository(repo, policy?)` audits one repository of the owner.
- `auditInstallation(policy?)` audits every repository the installation
  reaches, as one central report.
- `revoke()` revokes the token.
- `free()` overwrites the token.

Call `revoke()` and then `free()` when the run ends.

A failure rejects with an `Error` named `AirlockError`. It has a `kind`:
`inputs`, `refused`, `policy`, `audit`, `central` or `render`. For `central`,
it also has the `step`, and the `status` and vetted `code` when a service
answered.

No output carries a credential. Each entry point redacts every string it
returns against the credentials it holds: the report, the error message and
the error code. `audit` holds the caller's token. `CentralSession.signIn`
holds the Entra credential, and a session holds Safe's installation token.
Each credential is matched as sent, form-encoded and JSON-escaped. A server,
proxy or host that echoes one, in a message, a header, a body or a rejection,
therefore cannot carry it out, whichever code path let the text through.

A token must be shaped like a GitHub token: 8 to 4096 letters, digits and
`_`. The caller's token is refused before any request when it is not. Safe's
minted token is refused at `token-request`, and revoked, when it is not. Every
encoding of such a value, escaped once or twice, is the value itself, so the
redactor matches it wherever it is echoed. The length floor means redacting
never rewrites ordinary text. The module installs no
panic hook, so a panic carries no message out. `secrets.test.mjs` feeds a
synthetic token through each reachable error path.

## Size budget

Size budget: **4194304 bytes** (4 MiB) for `airlock_bg.wasm`, the module
wasm-bindgen writes.

`task wasm:size` runs `scripts/check-wasm-size.sh`, which reads the budget
from the line above and fails CI when the module is larger. The script also
prints the gzipped size, for information.

The module was 3,081,684 bytes (998,253 gzipped) when the budget was set. The
re-plan's proof measured 3.02 MB raw and 0.96 MB gzipped at `opt-level = "z"`
without central sign-in. Cloudflare counts only the uncompressed size of a
Worker, against 64 MiB on both plans, and allows 1 s of startup
([Workers limits](https://developers.cloudflare.com/workers/platform/limits/),
read 2026-11-21). The budget sits well inside both limits. It leaves room for
the checks still to come, and it catches a dependency that doubles the
module. Raise it only with the reason in the same change.

## Tests

`task wasm:test` runs `scripts/test-wasm.sh`. The script builds the native
parity binary and runs `node --test` on `crates/wasm/tests/*.test.mjs`
against the built module:

- `central.test.mjs`: central sign-in against fake Entra ID, Key Vault and
  GitHub, each refusal, and an audit on Safe's token. No output carries a
  secret marker.
- `host.test.mjs`: every path that reads time, the checks on each value the
  host returns, and the transport guards.
- `secrets.test.mjs`: a synthetic token, secret and assertion echoed in every
  error path the module can reach, and absent from every output.
- `parity.test.mjs`: the same audit natively, through reqwest, and as the
  module under Node, through `fetchHost`. Both run against the recorded
  responses one local server replays. Both runs must make the same requests
  and give the same findings document.

The fields that differ between two live runs, and that parity leaves out, are:

- `repository.settings_observed_at`, the server's `Date` header.

From one recording these agree too, and the test then compares the
documents whole.

The recording is `crates/wasm/tests/fixtures/audit-airlock.json`. It holds
GitHub's responses to an audit of `wyrd-company/airlock` against
`docs/examples/org-airlock.yml`. It keeps no request header, and its token is
the placeholder `ghu_PLACEHOLDER`. To make it again, run this with any token
that can read the repository:

```sh
AIRLOCK_RECORD_TOKEN=... cargo run -p airlock-wasm --example record_audit -- \
  wyrd-company airlock \
  'wyrd-company/airlock:docs/examples/org-airlock.yml@<sha>' \
  crates/wasm/tests/fixtures/audit-airlock.json
```

The recorder answers the placeholder's verification itself. It writes
nothing when the recording contains the token, or anything shaped like a
GitHub token.

## CI

The `WebAssembly` job in `.github/workflows/ci.yml` runs `task wasm` on every
pull request: build, size budget, then tests. `task lint` also runs clippy on
the core and the module for `wasm32-unknown-unknown`.
