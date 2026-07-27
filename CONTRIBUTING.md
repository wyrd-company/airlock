# Contributing

## Before you open a pull request

Run `task check`. It runs everything CI runs, so a green local run and a green
pull request mean the same thing.

## Commits and pull request titles

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Pull requests are squash merged, so the pull request title becomes the commit on
`main` — it is validated by a required check and is worth writing carefully.

History is linear. Merge commits are disabled.

## Scope of a change

Airlock never writes to a repository it audits. A change that adds a mutating
API call, accepts a write-capable credential, or falls back to an ambient token
will not be accepted, regardless of how convenient it is.

New checks come with the evidence they report and the remediation they suggest.
A finding that says only that something failed is not finished.

## Reporting a problem

Open an issue describing the repository state, the policy in use, and what
airlock reported versus what you expected. A findings document from
`--format json` is the most useful thing you can attach.
