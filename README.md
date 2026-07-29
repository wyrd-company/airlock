# airlock

[![CI](https://github.com/wyrd-company/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/wyrd-company/airlock/actions/workflows/ci.yml)

Audits a GitHub repository against a declared release-readiness policy and
reports what would block a release.

A policy names the checks that apply and how severely each one counts. Airlock
resolves that policy, runs the checks against the repository through the GitHub
API, and prints a findings document. It never writes: the credential it accepts
is verified to be read-only before first use, and a token carrying any write
permission is refused.

## Install

Not yet published to any registry. Build from source:

```sh
cargo install --git https://github.com/wyrd-company/airlock airlock-cli
```

The minimum supported Rust version is 1.86.

## Quickstart

Acquire a read-only credential, then audit a repository:

```sh
airlock auth login
airlock audit wyrd-company/airlock
```

With no `--policy`, airlock reads `{owner}/.github:airlock/policy.yml` for the
audited repository's owner. Airlock ships no built-in policy, so a repository
whose owner has none cannot be audited — that is an error, not an empty run.

Output is text on a terminal and JSON otherwise, so piping needs no extra flag:

```sh
airlock audit wyrd-company/airlock --policy ./policy.yml | jq '.summary'
```

At the end of an agent's work, `agent-work` re-runs the same audit and projects
its findings into the agent's file-change lanes:

```sh
airlock agent-work wyrd-company/airlock --working-tree .
```

Its `agent_lane` contains failed rules classified as `deterministic-file` or
`judgment-file`, keyed by rule id and carrying the remediation code and the
change it would make. `operator_deferred` separately identifies failed
`operator-setting` rules and failures that declare no remediation; neither
gates the command. `needs_decision`, `unsettled`, `manual`, and `suppressed`
keep the other unfinished or authorized-but-unaligned findings visible with
their counts and identities. Undecided items say whether they gate and retain
their evidence code, so a missing capability declaration is distinct from a
retryable observation failure. Every group retains each finding's observation
source, and the top-level `observation` block says whether file findings came
from the API tree or the local working tree.

This is a lane-scoped definition-of-done check, not an audit substitute or a
repository conformance claim. A clear agent lane can coexist with operator
work, manual judgment, suppressed debt, and other repository gaps; run
`airlock audit` for the complete findings authority.

`airlock audit --list-checks` prints the whole check registry: every rule id,
its statement, its severity, and whether airlock evaluates it mechanically,
reports it for a human, or has not built it yet.

## What the exit code means

| Code | Outcome         | Meaning                                                  |
| ---- | --------------- | -------------------------------------------------------- |
| `0`  | `conformant`    | Every enabled rule was decided; the gate is satisfied     |
| `1`  | `nonconformant` | Every enabled rule was decided; a gating rule failed      |
| `2`  | `incomplete`    | A gating rule was left undecided, or the run never started |

On Unix, a closed output pipe terminates silently on signal 13 (`SIGPIPE`),
commonly reported by shells as status 141.

`airlock agent-work` uses the same numeric codes for a different, explicitly
lane-scoped question:

| Code | Outcome                   | Meaning                                                        |
| ---- | ------------------------- | -------------------------------------------------------------- |
| `0`  | `agent_lane_clear`        | No deterministic or judgment file failure remains              |
| `1`  | `agent_lane_work_remains` | At least one deterministic or judgment file failure remains    |
| `2`  | `could_not_settle`        | The audit left a gate-relevant question unanswered or could not run |

Operator-setting failures are always counted and identified in
`operator_deferred`, but do not change code `0` to code `1`. Code `0` therefore
means only “my lane is clear”; it never means “the repository is aligned.”

The distinction is the point. An audit that could not evaluate an enabled rule
— because it is not built yet, because a bounded scan ran out of budget, or
because GitHub refused the request — never reports success. Every rule the
policy enables produces exactly one finding, with one of eight statuses:

`pass`, `fail`, `manual` (a judgment call for a human), `suppressed`,
`skipped` (a capability condition was not met), `unimplemented`,
`inconclusive` (a bound was hit), `error` (an API failure, with its cause).

`manual`, `suppressed`, and `skipped` are conclusive and never gate. The other
three leave the assertion undecided, and at a gating severity they make the
whole audit incomplete.

Incomplete input can never produce a clean result. A listing that stopped at
the page budget, a recursive tree GitHub truncated, or a response airlock could
not decode all make the assertions that depend on them inconclusive — airlock
does not conclude "no tag carries a `v` prefix" from the tags it happened to
read, or "no agent harness configuration is committed" from part of a tree.
Requests carry connect and read timeouts and the whole run carries a wall-clock
budget; exhausting either is a refusal before verification and an error finding
after it.

## Remediation lanes

Every registered rule declares, as compiled-in data, what closing its gap
takes. Each finding carries that declaration in `remediation_class`: a stable
code, what the change would be, whether it is reversible, and the lane it
travels in — or `none_reason` when airlock offers no remediation. Airlock
itself never performs any of them; the classification tells the consumer who
can.

| Lane                 | What it means                                                                                              | Who does the work                    |
| -------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `deterministic-file` | The same gap resolves to the same file content in every repository                                          | Closed headlessly, delivered as a PR |
| `judgment-file`      | The fix is repository-specific file content — prose, or configuration wired to this repository's toolchain | An agent authors it; a human reviews |
| `operator-setting`   | The fix sits behind the administration API, and `administration: write` is indivisible                     | A human, behind the TUI              |
| *(none)*             | A human attestation, a fix outside the repository, or history surgery airlock will not automate            | Nobody — the reason says why         |

The classification is not part of the registry digest. The digest attests what
every rule means and how it is evaluated — the contract a policy binds to with
`requires-registry`. Remediation is airlock's answer to a gap, and a better
answer must not invalidate policy compatibility.

## Two observation sources

File-level rules can be observed two ways; platform rules only one.

- **API tree** (the default): every git-backed fact is read from GitHub at a
  single resolved commit. This is the source for scheduled audits, the
  Action, and any run without a checkout. Airlock never requires a clone.
- **Local working tree** (`--working-tree <path>`): file-level rules are read
  from a checkout on disk, **as it stands** — including uncommitted and
  untracked content, because that is what an agent that just wrote changes is
  asking about. Gitignored files are excluded: a rule satisfied only by an
  ignored file is not satisfied. Tracked files are still read even when an
  ignore rule matches them.

Platform rules — settings, rulesets, tags, history, secrets — have no local
equivalent and are never inferred from a working tree. With a repository and
a credential (`airlock audit owner/repo --working-tree .`) they still come
from the API and the run mixes sources; without a credential
(`airlock audit --working-tree . --policy ./policy.yml`) they are reported as
`inconclusive` with evidence `not_observed` — never as passing — and the
audit is `incomplete` at any gating severity.

Every finding carries a `source` field naming what decided it (`api` or
`working-tree`; null when nothing observed it), and the report carries an
`observation` block stating the run's terms: which source served each half,
the working tree's HEAD commit, and whether the tree was dirty. "Clear
against an unpushed working tree" and "clear against the default branch" are
different facts; the output never lets one wear the other's words. A local
result with `dirty: true` describes something not yet committed, and a
working-tree run that had to assume the default branch says so with
`default_branch_observed: false`.

## Policy

The policy is YAML. It selects sections of the check registry through
capabilities, refines individual rules, and decides who may suppress what.
It expresses no logic of its own: the checks are the only place logic lives.

```yaml
version: 1
name: wyrd-company
requires-registry: ">=0.2"    # the binary's registry must satisfy this
gate: blocking                # which failing severities count: blocking | required

capabilities:
  base: [identity, licensing, files, git, automation]
  registry: [release]

apply:
  base: always
  registry:
    when: intentional-config-present

checks:
  REPO-META-06:
    params: { min-topics: 3, max-topics: 8 }
  REPO-FILE-10:
    severity: observation
  REPO-DOCS-04:
    enabled: false

suppressions:
  direct:
    - rule: REPO-CI-07
      repository: wyrd-company/airlock
      reason: "the reconcile workflow holds a credential"
  allow-repo-requests: [REPO-DOCS-01, REPO-DOCS-02]

reference-data:
  topics: wyrd-company/.github:airlock/topics.yml
```

Anything airlock does not recognise — an unknown key, section, rule id,
parameter, severity, or condition — is an error, never a silently narrower
audit. `--policy owner/repo:path[@ref]` names a policy explicitly, and
`--policy ./path` reads a local one for development.

Before any check runs, the policy and every transitive reference are resolved
to immutable identities — a commit and blob sha for remote sources, a content
hash for local ones — and hashed into a **policy bundle digest** that travels
in every result alongside the registry version and digest. Two runs that agree
on those three values ran the same rules against the same policy.

Each source is also reported individually under `policy.sources`, with what it
pinned to, so a reader who sees the bundle digest move can tell which reference
moved it:

```json
"sources": [
  {
    "name": "topics",
    "source": "wyrd-company/.github:airlock/topics.yml",
    "commit": "def456…",
    "blob_sha": "abc789…",
    "content_digest": "sha256:…"
  }
]
```

Suppression authority lives in the policy. An audited repository's
`.github/airlock.yml` holds *requests*:

```yaml
version: 1
suppress:
  - rule: REPO-DOCS-01
    reason: "docs are design notes until the first release"
```

A request is honoured only where the policy's `allow-repo-requests` names that
rule, and the honoured finding records both the request's reason and the
policy's authorisation. Anything else leaves the finding exactly as it was and
records the attempt in `policy_observations`. The repository being judged never
controls the exceptions to the judge.

Worked examples are in [`docs/examples/`](docs/examples/).

## Credentials

Airlock reads a token from `--token`, `--token-file`, or `--token-stdin` first,
then `AIRLOCK_TOKEN`, then the profile written by `airlock auth login`.

It deliberately ignores `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential store,
and git credential helpers. A tool that refuses write access should not quietly
pick up the write-capable credential already sitting in your environment.

`--token` puts a credential in your shell history and in process listings.
Prefer `--token-file` or `--token-stdin`.

Every token is verified before its first use, and the rule is positive
enumeration: airlock accepts a token only when it can list the token's whole
grant and every entry in that list is a read.

- **`ghu_`**, issued by the Airlock Safe app: every installation the token can
  reach is listed, across every page, and each must be attested to that app by
  **both** its numeric app id and its slug — an id survives a rename, a slug
  does not — and must carry only `read` permissions.
- **`ghp_` / `gho_`**: the exact scopes from `X-OAuth-Scopes` must all appear on
  a closed, reviewed list of scopes whose full authority is read-only. An
  unknown scope is refused rather than assumed safe, a missing header is an
  unread grant rather than an empty one, and a response carrying the header
  twice has no single answer and is refused too.
- **`github_pat_`**, **`ghs_`**, and unknown prefixes are refused as
  unverifiable. GitHub offers no way to enumerate a fine-grained token's
  permissions, and probing for write access would break the read-only contract
  airlock exists to keep.

`airlock auth status` says which source would be used and what it grants.
`airlock auth login` runs the device flow and stores the result at
`$XDG_CONFIG_HOME/airlock/config.toml`, created `0600` before anything is
written to it, replaced atomically, and refused on later runs if it has become
a symlink or readable by anyone but you.
`airlock auth token --profile <name>` verifies a stored profile and writes only
its token to standard output; see [Provisioning CI](#provisioning-ci).

### Provisioning CI

The repository's dogfood job accepts only an `AIRLOCK_TOKEN` minted by the
Airlock Safe GitHub App. The supported CI credential is a non-expiring `ghu_`
user access token:

1. An operator disables **Expire user authorization tokens** in the Airlock
   Safe app's optional features.
2. The operator runs `airlock auth login --profile ci` and approves the device
   flow in the browser. With expiry disabled, the profile stores the access
   token without an expiry or refresh token.
3. The operator runs `airlock auth token --profile ci`. Airlock verifies the
   stored token is Airlock-Safe-issued and wholly read-only before writing only
   the token to standard output.
4. The operator pipes that value into the `AIRLOCK_TOKEN` Actions repository
   secret for `wyrd-company/airlock`:

   ```bash
   airlock auth token --profile ci |
     gh secret set AIRLOCK_TOKEN --repo wyrd-company/airlock
   ```

   If the receiving command exits before reading the token, Airlock follows
   normal Unix pipe semantics: it exits silently on `SIGPIPE` (signal 13,
   commonly reported by shells as status 141) rather than printing a panic.

Treat the output of `airlock auth token` as a secret: keep it out of shell
history, logs, and shared terminals. The dogfood job runs the real audit
whenever the repository secret is present and reports a graceful skip when it
is absent.

This chooses a long-lived credential to avoid giving CI any write authority.
GitHub rotates refresh tokens on every exchange, so refreshing in a job would
either require forbidden `secrets: write` access to persist the successor or
leave later and concurrent jobs with a stale token. The accepted trade-off is
a long-lived token whose permissions are read-only by app registration and are
verified again by Airlock before every audit. To rotate it, repeat the device
flow and replace the repository secret.
