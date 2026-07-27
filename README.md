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

> The audit is under construction. The commands below are the target shape;
> today every subcommand exits 2 and says it is not implemented.

Acquire a read-only credential, then audit a repository:

```sh
airlock auth login
airlock audit wyrd-company/airlock --policy wyrd-company/.github:airlock/policy.yml
```

Exit codes carry the result: `0` when nothing blocking was found, `1` when there
are blocking findings, `2` when the audit could not be run at all.

Output is text on a terminal and JSON otherwise, so piping needs no extra flag:

```sh
airlock audit wyrd-company/airlock --policy ./policy.yml | jq '.summary'
```

## Credentials

Airlock reads a token from `--token`, `--token-file`, or `--token-stdin` first,
then `AIRLOCK_TOKEN`, then the profile written by `airlock auth login`.

It deliberately ignores `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential store,
and git credential helpers. A tool that refuses write access should not quietly
pick up the write-capable credential already sitting in your environment.
