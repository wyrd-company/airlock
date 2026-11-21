---
relationships:
  references:
    - wasm.md
    - ../action.yml
  implemented-by: ../action/src/main.mjs
---

# The Airlock action

The Airlock action audits the repository that runs it, in repository mode, on
the run's own `GITHUB_TOKEN`. It is a composite action of three steps:

1. `actions/setup-node`, pinned by commit, sets up Node 24.22.3, with its
   package-manager cache off: the caller's `package.json` is not the
   action's. **The action's Node stays first on the job's `PATH` for the
   caller's later steps.** A later step that needs another Node sets it up
   itself.
2. A `run` step, in `sh`, runs `action/step.sh`. That starts the pinned Node
   on the committed `dist/index.mjs` with an allowlisted environment (see
   [the audit step's environment](#the-audit-steps-environment)). It loads
   the engine from `dist/airlock_bg.wasm` (see
   [the WebAssembly module](wasm.md)), audits, and stages the findings
   document for upload.
3. `actions/upload-artifact`, pinned by commit, uploads the staged document,
   even when step 2 failed. A composite's `run` step gets no Actions runtime
   credential, so only an action can upload.

No step installs Rust or runs Cargo, and no Rust binary is published for it.

The action is a composite, not a `node24` action, for the run's own token.
The second step sets `AIRLOCK_RUN_TOKEN` to `${{ github.token }}` in its own
`env`. A step's own `env` wins over the job's and the calling step's, so a
caller's variables cannot replace it. An input could be set to any token: a caller
holding another App's installation token could pass it as both the
credential and the run's token, and the job's read permissions would be
recorded as its grant. The CI job "Action: a forged run token is refused"
runs exactly that attempt on GitHub's runners, and the action refuses it.
The same step takes the run's repository, workflow, commit, job and API
address from the `github` and `runner` contexts, not from the caller's
environment.

## The audit step's environment

A caller's job environment reaches every step, and a variable can load code
into Node (`NODE_OPTIONS`), send its requests through a proxy of the caller's
choosing (`NODE_USE_ENV_PROXY` with `HTTPS_PROXY`), accept that proxy's
certificate (`NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS`,
`SSL_CERT_*`), or preload a library (`LD_PRELOAD`). A list of such names to
blank never ends, so the audit step keeps an allowlist instead:

- The step runs in `sh`, which is dash on GitHub's Linux runners. Dash
  imports no functions from the environment, unlike bash with its
  `BASH_FUNC_*` variables, and reads `$ENV` only when interactive. The
  step's own `env` blanks `BASH_ENV` and `ENV` as well.
- `action/step.sh` checks the Node that setup-node installed in the runner's
  tool cache (`<tool cache>/node/24.22.3/<x64|arm64>/bin`), including its
  `--version`. It then starts that Node through `/usr/bin/env -i`, by
  absolute path.
- Node receives these variables and no others: `PATH` (that bin directory,
  then `/usr/bin:/bin`), `HOME`, `RUNNER_TEMP`, `GITHUB_ACTIONS`,
  `GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_ACTION`, `GITHUB_RUN_ID`,
  `GITHUB_RUN_ATTEMPT`, `GITHUB_REPOSITORY`, `GITHUB_REPOSITORY_ID`,
  `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_JOB`,
  `GITHUB_API_URL`, the `INPUT_*` values, `AIRLOCK_JOB_CHECK_RUN_ID` and
  `AIRLOCK_CREDENTIALS_ON_STDIN`.
- The three credentials (the `token` input, `AIRLOCK_TOKEN` and the run's
  own token) reach Node on its standard input, so they appear in no
  process's arguments or environment.

`action/tests/action.test.mjs` runs `step.sh` with every such variable set,
including a `BASH_FUNC_` function, and checks that Node received the
allowlist alone and audited directly. The CI job "Action: a forged run
token is refused" does the same on GitHub's runners, with `NODE_OPTIONS`,
`BASH_ENV` and proxy legs.

setup-node and upload-artifact are Node actions, which the runner starts with
the job's environment, and an action cannot start them any other way. Each
blanks `NODE_OPTIONS`, `NODE_USE_ENV_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`,
`NODE_TLS_REJECT_UNAUTHORIZED`,
`NODE_EXTRA_CA_CERTS`, `LD_PRELOAD` and `LD_LIBRARY_PATH` in its own `env`.

## Requirements

- **Direct TLS to `GITHUB_API_URL`.** The audit ignores every proxy variable
  and `NODE_EXTRA_CA_CERTS`, and trusts only Node's own CA bundle. A
  self-hosted runner behind a TLS-inspecting proxy is not supported: there
  every request fails, and the audit is refused as `run_token_unconfirmed`.
- **A Linux runner, x64 or arm64**, with `/bin/sh` and `/usr/bin/env`, as
  GitHub's hosted runners have.

Repository mode is the only mode. The central audit of every repository of an
owner is the Airlock Worker's scheduled audit, not the action's.

## Use

```yaml
permissions: {}
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      attestations: read
    steps:
      - name: Audit this repository
        uses: wyrd-company/airlock@<full commit SHA> # <release tag>
        with:
          mode: repository
          token: ${{ github.token }}
          policy: ${{ github.repository_owner }}/.github:airlock/policy.yml
```

This is the `with:` block the `airlock-config` template renders. The
repository does not need to be checked out: the engine reads everything
through the GitHub REST API. Pin the full commit SHA of a release tag, with
the tag as the comment.

The job must declare its permissions, and every one must be `read`, or
`read-all`. The action reads them from the workflow file at
`GITHUB_WORKFLOW_SHA` and refuses the token for any other level, `write` and
`none` included. It also refuses the token when the job declares none,
because the token then holds the repository's defaults. A job that calls a
reusable workflow is refused too.

## Inputs

| Input | Default | Meaning |
| ----- | ------- | ------- |
| `mode` | `repository` | `repository`, the only mode. Any other value is refused. `central` is refused with a message that names the Airlock Worker's scheduled central audit. |
| `token` | none | The run's own token, `${{ github.token }}`. Without it, `AIRLOCK_TOKEN` from the step's environment is read. Another credential must be one Airlock can verify as read-only. |
| `repository` | `GITHUB_REPOSITORY` | `owner/repo` to audit. The run's own token audits the run's repository only. |
| `policy` | `{owner}/.github:.github/airlock.yml` | The policy, as `owner/repo:path[@ref]`. A local path is refused: the engine reads no file system. |
| `ref` | default branch | A commit, branch or tag to audit. |
| `format` | `json` | `json` or `text`. |
| `fail-on-incomplete` | `true` | `false` lets an incomplete audit succeed. It covers a missing or refused token too. Only repository mode honours it, so a refused mode always fails. |

The composite action's central-mode inputs are removed: `app-id`,
`key-name`, `installation-repositories`, `vault-url`, `azure-tenant-id` and
`azure-client-id`. So is its `airlock-central-report` artifact. GitHub warns
about an input an action does not declare, and the action ignores it.

## Outputs

| Output | Meaning |
| ------ | ------- |
| `outcome` | `conformant`, `nonconformant` or `incomplete`. Waived, routed, unbuilt and out-of-scope rules do not affect it. |
| `complete` | `true` when the audit completed without a run error. |
| `findings-location` | The absolute path of the findings document on the runner. |
| `artifact` | The name of the artifact the document was uploaded as. |

The action also exports `AIRLOCK_FINDINGS`, `AIRLOCK_OUTCOME` and
`AIRLOCK_COMPLETE` to later steps.

The step succeeds when the outcome is `conformant`. It fails when the outcome
is `nonconformant`. It fails when the outcome is `incomplete`, unless
`fail-on-incomplete` is `false` in repository mode.

## The report artifact

The action uploads the findings document as the artifact
**`airlock-findings-<job.check_run_id>`**, and its `artifact` output names it.
The artifact holds one file, `airlock-findings.json`, or
`airlock-findings.txt` with `format: text`. The Airlock Worker reads the
newest artifact whose name starts with `airlock-findings-` for each
repository. The upload happens on every run, a refused one included, so the
Worker sees why a repository was not audited. A failed upload fails the step.

An artifact name must be unique within a workflow run attempt. The job's
check run id is unique to each job, each leg of a matrix and each attempt,
so several jobs, a matrix and a re-run each upload their own. Two runs of the
action in the same job would share the name, so a job runs it once. A runner
that does not provide `job.check_run_id` gets
`airlock-findings-<job id>-<run attempt>`, which a matrix would share.

Remove any step of your own that uploads the findings as `airlock-findings`:
the composite action this replaces asked callers to add one, and the action
now uploads the report itself.

When the engine does not audit, the document is a stable incomplete one:

```json
{"outcome":"incomplete","complete":false,"mode":"repository","message":"..."}
```

The message is the action's own, or the engine's refusal, which the engine
has already redacted. An empty document is never published.

## What the action proves

The run's job declares its permissions, and the run's own token holds those
and no more. The action admits an installation token only once it has placed
it as the run's own, by what a caller cannot forge:

1. **The token's form**, before anything is sent. It must be
   `ghs_15368_<JSON Web Token>`, the form GitHub mints `GITHUB_TOKEN` in, where
   15368 is the GitHub Actions app. Another App's installation token, a token
   with the app id dropped, and a legacy `ghs_` token are refused as
   `not_actions_token`. GitHub refuses a token whose app id was edited, so
   the prefix names the app that minted it.
2. **GitHub's answer**, as the first request. `GET /installation/repositories`
   must list exactly one repository, read to the last page with
   `total_count` 1, whose id and full name are `GITHUB_REPOSITORY_ID` and
   `GITHUB_REPOSITORY`. Anything else is refused as `run_repository_mismatch`,
   and a failed request as `run_token_unconfirmed`. Only then is the workflow
   file read and the audit run.
3. **The binding to `AIRLOCK_RUN_TOKEN`**, which the step sets from
   `github.token`. The token input must equal it.

**Covered:**

- **The inputs.** None of them can name the run's token.
- **Forged tokens.** The engine's own checks refuse any installation token
  that is not the GitHub Actions app's for this repository, even when
  `AIRLOCK_RUN_TOKEN` was rewritten to match.
- **The caller's variables, in the audit step.** Node receives only the
  allowlist above, so no other variable the caller sets reaches the engine:
  no `NODE_*`, `*_PROXY`, `SSL_CERT_*`, `LD_*` or TLS override.
- **The variables setup-node and upload-artifact blank**, listed above.

**Not covered:**

- **Another `GITHUB_TOKEN` of the same repository**, from another job or run,
  perhaps with write permissions. Nothing in the token or in GitHub's answer
  tells two jobs' tokens apart, so the job's declared permissions are recorded
  as its grant.
- **Code the caller runs in the job.** A job can run code before the action,
  replace `dist/`, the tool cache's Node, or the staged report, or fake the
  artifact.
- **The job's environment, in the two GitHub-maintained steps.** setup-node
  and upload-artifact run with the job's environment, less the names they
  blank. A variable not on that list can still influence them in ways no
  action can fully prevent: for example, how setup-node finds or fetches
  Node, or what upload-artifact uploads. The lower-case `https_proxy` and
  `http_proxy` are such variables. When Actions loads `action.yml`, it reads
  `env` names without regard to case and refuses `https_proxy` beside
  `HTTPS_PROXY`, yet it exports both to the step, so the action cannot blank
  the lower-case forms. CI
  [run 44925829010](https://github.com/wyrd-company/airlock/actions/runs/44925829010)
  shows it: with a dead `https_proxy` in the job's env, the audit reached
  GitHub directly, and upload-artifact failed through the proxy.

A repository's own audit is therefore evidence about the repository, not
proof against its own workflow's author. The Airlock Worker's scheduled
central audit is the authoritative one: the repository's workflow cannot
reach it.

### Assumption: GitHub's token form

GitHub does not document the claims or the form of an installation token,
and asks clients to treat it as opaque
([changelog, 2026-10-02](https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/)).
The checks above rest on what was observed on GitHub's runners on 2026-11-21:

- The run's token is `ghs_15368_<JWT>`, 377 characters. Its JWT header is
  `ES256`, and its claims are only `aud`, `iss`, `iat`, `exp`, `jti`, `ver`
  and an opaque `ctx`. It carries no app or repository claim, so the claims
  cannot place it
  ([observation](https://assets.wyrd.foo/airlock/pr-25/round-2/run-token-observation-44921627383.txt)).
- GitHub accepts the genuine token and answers 401 when its app id is edited
  to another, dropped, or the token is sent as `ghs_<JWT>`
  ([probe](https://assets.wyrd.foo/airlock/pr-25/round-2/run-token-prefix-probe-44921669851.txt)).
- `GET /installation/repositories` with the run's token lists the run's
  repository alone
  ([probe](https://assets.wyrd.foo/airlock/pr-25/round-2/run-token-reach-44921784323.txt)).

If GitHub changes the form, repository mode refuses every run's token with a
message that names the form it expects and says GitHub may have changed it.
It fails closed, and Airlock must then be updated.

The second check also rests on TLS to `GITHUB_API_URL`: GitHub's answer
proves the token's place only if it is GitHub's. The audit step therefore
ignores every proxy and CA variable, as
[the audit step's environment](#the-audit-steps-environment) describes.

## Tokens

The action masks `token` and the run's own token with `core.setSecret` before it
prints or writes anything, so the runner replaces either value in the log.
The engine redacts both from every string it returns, as
[the module's redaction](wasm.md#entry-points) describes. The action
redacts them once more from everything it writes. No output, exported
variable, findings document or artifact carries either token.
`action/tests/action.test.mjs` shows this against a GitHub that echoes the
token in every answer.

The action makes no request that writes. Its only write is the report
artifact, through the Actions runtime's own credential. It never uses the
token for that.

## Build

```sh
task wasm:install     # the wasm32 target and the locked wasm-bindgen
task action:install   # the action's locked JavaScript dependencies
task action:build     # dist/index.mjs and dist/airlock_bg.wasm
```

`scripts/build-action.sh` builds the module into `target/action-pkg` and
bundles `action/src/index.mjs` with esbuild into `dist/index.mjs`. It then
copies the module beside the bundle. It refuses to run on any `rustc` but
the one it names, **1.100.0**, because another toolchain gives other bytes.
The module build maps the Cargo home and the checkout to fixed paths, so the
module is the same on every machine.

Commit `dist/` with any change to the engine, the action's source or its
dependencies. The `Action` job in `.github/workflows/ci.yml` runs
`task action`. It rebuilds `dist/` with that toolchain, fails on any
difference from the committed copy, then runs the action's tests. To change
the toolchain, change it in `scripts/build-action.sh` and in that job
together, and commit the rebuilt `dist/`.

## Tests

`task action:test` runs the action's tests. `action/tests/main.test.mjs` runs
`main.mjs` with a fake engine that echoes the token, which proves the
action's own redaction apart from the engine's. `action/tests/action.test.mjs`
starts `dist/index.mjs` as the action's step does, against a local server
that replays the module's recording as GitHub's API, and reads the staged
artifact. The upload step runs only on GitHub: the CI job "Action: a forged
run token is refused" and `audit.yml` run it. The tests cover these cases:

- the template's `with:` block, end to end, with the staged artifact;
- text format;
- a job with a write permission;
- a token outside Actions;
- `central` and every other mode, with and without `fail-on-incomplete`;
- invalid inputs and a local policy;
- an installation token other than the run's own;
- the forged pair: another App's installation token as the credential, with
  `run-token` set as an input;
- an artifact name for each job, attempt and matrix leg;
- a report that cannot be staged;
- `action/step.sh` with every hostile variable set: Node gets the allowlist
  alone, audits directly past a dead proxy, never runs the caller's
  `NODE_OPTIONS`, and receives no credential in its environment; a forged
  pair through the step; a Node other than the pinned one;
- every output free of the token when GitHub echoes it.

## Release

The action is released as a tag of this repository. The tag carries
`action.yml`, `dist/index.mjs` and `dist/airlock_bg.wasm`. Callers pin the
tag's full commit SHA. The operator makes every release.
