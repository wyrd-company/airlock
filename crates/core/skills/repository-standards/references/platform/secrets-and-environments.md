# Secrets, Variables, and Environments

Read only when provisioning or altering a secret, variable, or environment. See
`README.md` in this folder.

## Placement rules

- An **app id is a variable**, not a secret. It is not confidential, and a
  variable can be read back to verify.
- A **private key is a secret**, held at **environment** scope wherever an
  approval boundary exists, and never copied to organization or repository
  scope.
- A repository is granted only what it uses.

A private key must never be copied to a file, artifact, log, task note, or chat.

**Environment scope is what survives `secrets: inherit`.** A reusable workflow
receives the caller's secret context through `inherit`, because a caller job
that has not entered an environment cannot resolve an environment-scoped secret
and therefore cannot pass one explicitly. Inheriting does not flatten the
scoping: a job that does not declare `environment:` still cannot read a secret
scoped to it.

That makes the placement rule above load-bearing rather than tidy. An
organization-scoped private key is readable by **every** job in a called
workflow; an environment-scoped one is readable only by the job that passed the
gate.

## Organization variables

| Name                       | Purpose                    |
| -------------------------- | -------------------------- |
| `RELEASE_AUTHORITY_APP_ID` | Release authority identity |
| `PACKAGE_TAGS_APP_ID`      | Package tag authority      |
| `DOCS_PUBLISHER_APP_ID`    | Docs tap publisher         |
| `DEPENDENCY_READER_APP_ID` | CI dependency reader       |
| `REPO_SETTINGS_APP_ID`     | Settings reconciler        |

## Organization secrets

| Name                                | Purpose                      |
| ----------------------------------- | ---------------------------- |
| `DOCS_PUBLISHER_APP_PRIVATE_KEY`    | Docs tap publisher key       |
| `DEPENDENCY_READER_APP_PRIVATE_KEY` | CI dependency reader key     |
| `REPO_SETTINGS_APP_PRIVATE_KEY`     | Settings reconciler key      |
| `NPM_TOKEN`                         | npm publication              |
| `CARGO_REGISTRY_TOKEN`              | crates.io publication        |
| `FORMULAE_PUBLISH_KEY`              | Homebrew tap formula updates |

## Environment secrets

Never stored at organization or repository scope.

| Name                                | Environment               | Purpose                            |
| ----------------------------------- | ------------------------- | ---------------------------------- |
| `RELEASE_AUTHORITY_APP_PRIVATE_KEY` | `stable-release-approval` | Release authority key              |
| `PACKAGE_TAGS_APP_PRIVATE_KEY`      | `package-tag-mutation`    | Package tag authority key          |
| `NPM_FIRST_PUBLICATION_TOKEN`       | `npm-first-publication`   | First publication of a new package |

## Repository secrets and variables

| Name                                                                           | Purpose                                      |
| ------------------------------------------------------------------------------ | -------------------------------------------- |
| `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_PROJECT_ID`, `CLOUDFLARE_PAGES_API_TOKEN` | Cloudflare Pages deployment                  |
| `vars.DEPLOY_TARGET`                                                           | Selects `cloudflare-pages` or `github-pages` |

## Environments

`stable-release-approval` · `package-tag-mutation` · `npm-first-publication` ·
`pub.dev` · `cloudflare-pages` · `github-pages`

An environment is the boundary that gates private-key access. Validation
completes in a job holding no key; a dependent job selects exactly one
environment and only then receives one.

**Environment deployment policies cannot be read by `GITHUB_TOKEN`.** They are
confirmed by the owner in repository settings, not by any automated check.

## Auditing references without reading this file

Secret and variable **names** appear in plain text in workflow source, so a
repository's consumption can be listed without any privileged read:

```bash
rg -oIN 'secrets\.[A-Za-z0-9_]+|vars\.[A-Za-z0-9_]+' .github/ | sort -u
```

An auditing agent checks those names against the **naming convention** stated in
`SKILL.md`. Checking them against this inventory is a platform activity, not an
audit activity.
