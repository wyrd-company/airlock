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

1. `actions/setup-node`, pinned by commit, sets up Node 24.22.3. The pinned
   Node stays first on the job's `PATH` for the steps after it.
2. A `run` step runs the committed `dist/index.mjs` on it. That loads the
   engine from `dist/airlock_bg.wasm` (see [the WebAssembly module](wasm.md)),
   audits, and stages the findings document for upload.
3. `actions/upload-artifact`, pinned by commit, uploads the staged document,
   even when step 2 failed. A composite's `run` step gets no Actions runtime
   credential, so only an action can upload.

No step installs Rust or runs Cargo, and no Rust binary is published for it.

The action is a composite, not a `node24` action, for the run's own token.
The second step sets `AIRLOCK_RUN_TOKEN` to `${{ github.token }}` in its own
`env`. A step's own `env` wins over the job's and the calling step's, so the
caller cannot replace it. An input could be set to any token: a caller
holding another App's installation token could pass it as both the
credential and the run's token, and the job's read permissions would be
recorded as its grant. The CI job "Action: a forged run token is refused"
runs exactly that attempt on GitHub's runners, and the action refuses it.
The same step takes the run's repository, workflow, commit, job and API
address from the `github` context, not from the caller's environment.

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
- every output free of the token when GitHub echoes it.

## Release

The action is released as a tag of this repository. The tag carries
`action.yml`, `dist/index.mjs` and `dist/airlock_bg.wasm`. Callers pin the
tag's full commit SHA. The operator makes every release.
