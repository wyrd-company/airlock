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

The minimum supported Rust version is 1.85.

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

`airlock audit --list-checks` prints the whole check registry: every rule id,
its statement, its severity, and whether airlock evaluates it mechanically,
reports it for a human, or has not built it yet.

## What the exit code means

| Code | Outcome         | Meaning                                                  |
| ---- | --------------- | -------------------------------------------------------- |
| `0`  | `conformant`    | Every enabled rule was decided; the gate is satisfied     |
| `1`  | `nonconformant` | Every enabled rule was decided; a gating rule failed      |
| `2`  | `incomplete`    | A gating rule was left undecided, or the run never started |

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

## Policy

The policy is YAML. It selects sections of the check registry through
capabilities, refines individual rules, and decides who may suppress what.
It expresses no logic of its own: the checks are the only place logic lives.

```yaml
version: 1
name: wyrd-company
requires-registry: ">=0.1"    # the binary's registry must satisfy this
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
  reach is listed, across every page, and each must be attested to that app and
  carry only `read` permissions.
- **`ghp_` / `gho_`**: the exact scopes from `X-OAuth-Scopes` must all appear on
  a closed, reviewed list of scopes whose full authority is read-only. An
  unknown scope is refused rather than assumed safe, and a missing header is an
  unread grant rather than an empty one.
- **`github_pat_`**, **`ghs_`**, and unknown prefixes are refused as
  unverifiable. GitHub offers no way to enumerate a fine-grained token's
  permissions, and probing for write access would break the read-only contract
  airlock exists to keep.

`airlock auth status` says which source would be used and what it grants.
`airlock auth login` runs the device flow and stores the result at
`$XDG_CONFIG_HOME/airlock/config.toml`, created `0600` before anything is
written to it, replaced atomically, and refused on later runs if it has become
a symlink or readable by anyone but you.
