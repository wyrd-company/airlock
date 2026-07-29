# Conformance Checklist

The audit surface for `repository-standards`. Every rule is a checkable
assertion.

**Always cite a rule by id and statement together.** `REPO-CI-02` alone is
meaningless to whoever reads the task later.

`REPO-GIT-09`, `REPO-TASK-04`, and `REPO-LIC-04` apply only when the
repository declares at least one release unit.

## Severity

| Level           | Meaning                                                             |
| --------------- | ------------------------------------------------------------------- |
| **Blocking**    | The repository should not be public in this state                   |
| **Required**    | A genuine gap; raise it                                             |
| **Observation** | Report it; it may be a deliberate choice or a not-yet-live practice |

## Identity

| Id             | Assertion                                                                                                                                                             | Severity    | How to check                                                       |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------------------------------------------------------------ |
| `REPO-ORG-01`  | The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good | Observation | Manual — Judgment |
| `REPO-ORG-02`  | A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company`                                                                   | Observation | Manual — Judgment |
| `REPO-NAME-01` | The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase                                                                                              | Required    | Repository name                                                    |
| `REPO-NAME-02` | A dotted name is used only where the repository is a deployable site and the name is its hostname                                                                     | Required    | Manual — Repository name |
| `REPO-NAME-03` | A repository in a product family carries the family prefix                                                                                                            | Observation | Manual — Repository name |
| `REPO-NAME-04` | The family prefix and the family topic agree                                                                                                                          | Required    | Manual — Name vs topics |
| `REPO-META-01` | `.github/repo-settings.yml` declares a description                                                                                                                    | Blocking    | File contents                                                      |
| `REPO-META-02` | The description is one sentence, at most 160 characters, and survives truncation at ~80                                                                               | Required    | File contents                                                      |
| `REPO-META-03` | The description expands any acronym on first use                                                                                                                      | Required    | Manual — Read it |
| `REPO-META-04` | The description contains no self-deprecation                                                                                                                          | Required    | Manual — Read it |
| `REPO-META-05` | The description agrees with the README's opening line                                                                                                                 | Required    | Manual — Compare |
| `REPO-META-06` | Between three and eight topics are declared                                                                                                                           | Required    | File contents                                                      |
| `REPO-META-07` | Topics include at least one artifact-type and one ecosystem term                                                                                                      | Required    | Compare against `topics.md`                                        |
| `REPO-META-08` | A repository in a product family carries the family topic                                                                                                             | Required    | Manual — Compare against `topics.md` |
| `REPO-META-09` | Any topic not in `topics.md` has been added to it                                                                                                                     | Required    | Compare against `topics.md`                                        |
| `REPO-META-10` | No org-name topic is declared                                                                                                                                         | Required    | File contents                                                      |
| `REPO-META-11` | The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted                                                         | Required    | File contents                                                      |
| `REPO-META-12` | `.github/repo-settings.yml` declares no `visibility` field                                                                                                            | Blocking    | File contents                                                      |
| `REPO-META-13` | Live GitHub metadata matches the declared file                                                                                                                        | Observation | `gh repo view` vs file — drift means reconciliation is not running |

## Licensing

| Id            | Assertion                                                                                                                                             | Severity    | How to check                                 |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | -------------------------------------------- |
| `REPO-LIC-01` | A `LICENSE` file exists                                                                                                                               | Blocking    | File presence                                |
| `REPO-LIC-02` | The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license | Required    | Manual — Judgment against the category table |
| `REPO-LIC-03` | The repository is not dual-licensed `MIT OR Apache-2.0`                                                                                               | Blocking    | `LICENSE`, package metadata                  |
| `REPO-LIC-04` | A repository publishing to a registry declares the license in package metadata                                                                        | Required    | `package.json`, `Cargo.toml`, `pubspec.yaml` |
| `REPO-LIC-05` | A plumbing repository's README states that the license covers packaging, not payload                                                                  | Required    | Manual — Read the README |
| `REPO-LIC-06` | A non-default license choice has a stated reason in the README or a decision record                                                                   | Observation | Manual — Read |

## Files

| Id             | Assertion                                                                                                            | Severity    | How to check                                 |
| -------------- | -------------------------------------------------------------------------------------------------------------------- | ----------- | -------------------------------------------- |
| `REPO-FILE-01` | `README.md` exists                                                                                                   | Blocking    | File presence                                |
| `REPO-FILE-02` | `CONTRIBUTING.md` exists in the repository, not only at org level                                                    | Required    | File presence                                |
| `REPO-FILE-03` | `.gitignore` exists and is ecosystem-appropriate                                                                     | Required    | File presence                                |
| `REPO-FILE-04` | `.gitattributes` exists and normalizes line endings                                                                  | Required    | File contents                                |
| `REPO-FILE-05` | `.editorconfig` exists                                                                                               | Required    | File presence                                |
| `REPO-FILE-06` | `taskfile.yml` exists, lowercase                                                                                     | Required    | File presence                                |
| `REPO-FILE-07` | `.github/workflows/` contains at least a CI workflow triggered on pull request                                       | Blocking    | File presence                                |
| `REPO-FILE-08` | `.github/renovate.json` exists and extends the org preset                                                            | Required    | File contents                                |
| `REPO-FILE-16` | `.github/repo-settings.yml` exists                                                                                   | Blocking    | File presence                                |
| `REPO-FILE-17` | `.github/workflows/audit.yml` exists and triggers on a schedule and on demand                                        | Blocking    | File contents                                |
| `REPO-FILE-09` | `.config/lefthook.yml` exists                                                                                        | Required    | File presence                                |
| `REPO-FILE-10` | `.devcontainer/` exists                                                                                              | Required    | File presence                                |
| `REPO-FILE-11` | `AGENTS.md` exists                                                                                                   | Required    | File presence                                |
| `REPO-FILE-12` | `CLAUDE.md` exists and is a symlink to `AGENTS.md`                                                                   | Required    | `git ls-files -s CLAUDE.md` — mode `120000`  |
| `REPO-FILE-13` | No agent harness configuration is committed — no `.claude/`, `.cursor/`, or equivalent                               | Required    | File presence                                |
| `REPO-FILE-14` | No `CODEOWNERS` file is present                                                                                      | Observation | File presence                                |
| `REPO-FILE-15` | Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs | Observation | Manual — Compare against the org `.github` repository |

## README

| Id               | Assertion                                                                  | Severity    | How to check                       |
| ---------------- | -------------------------------------------------------------------------- | ----------- | ---------------------------------- |
| `REPO-README-01` | Opens with a title and a one-line statement of what it is                  | Required    | Manual — Read |
| `REPO-README-02` | Badges are present                                                         | Required    | Manual — Read |
| `REPO-README-03` | An installation section covers every supported channel                     | Blocking    | Manual — Compare against published channels |
| `REPO-README-04` | A quickstart or usage section contains at least one real, runnable example | Blocking    | Manual — Read |
| `REPO-README-05` | A repository with a user interface has an animated demo                    | Observation | Manual — Read |
| `REPO-README-06` | Where a demo exists, its `.tape` source is committed                       | Required    | File presence                      |
| `REPO-README-07` | Prerequisites appear only where non-obvious                                | Observation | Manual — Read |
| `REPO-README-08` | No license section                                                         | Required    | Manual — Read |
| `REPO-README-09` | No contributing section                                                    | Required    | Manual — Read |

## Git configuration

| Id            | Assertion                                                                                                                   | Severity    | How to check                                          |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------------------- |
| `REPO-GIT-01` | The default branch is `main`                                                                                                | Required    | `gh repo view --json defaultBranchRef`                |
| `REPO-GIT-02` | The repository is covered by organization-sourced rulesets on its default branch                                            | Blocking    | `gh api repos/{o}/{r}/rulesets?includes_parents=true` |
| `REPO-GIT-03` | Those rulesets require pull requests, allow only squash and rebase, and require linear history                              | Blocking    | `gh api repos/{o}/{r}/rules/branches/main`            |
| `REPO-GIT-13` | A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY` | Required    | Workflow source                                       |
| `REPO-GIT-14` | No secret or variable is named after the task that introduced it                                                            | Required    | Manual — Workflow source |
| `REPO-GIT-04` | Merge commits are disabled                                                                                                  | Required    | `gh repo view --json mergeCommitAllowed`              |
| `REPO-GIT-05` | Squash merge is enabled                                                                                                     | Required    | `gh repo view --json squashMergeAllowed`              |
| `REPO-GIT-06` | Auto-delete head branch on merge is enabled                                                                                 | Required    | `gh repo view --json deleteBranchOnMerge`             |
| `REPO-GIT-07` | Wikis, Projects, and Discussions are off unless deliberately used                                                           | Observation | `gh repo view`                                        |
| `REPO-GIT-08` | Tags carry no `v` prefix                                                                                                    | Required    | `git tag`                                             |
| `REPO-GIT-09` | Multi-release-unit tags use `@scope/name@version`                                                                           | Required    | `git tag`                                             |
| `REPO-GIT-10` | History contains no merge commits                                                                                           | Required    | `git log --merges`                                    |

## Automation

| Id             | Assertion                                                                                        | Severity | How to check                                 |
| -------------- | ------------------------------------------------------------------------------------------------ | -------- | -------------------------------------------- |
| `REPO-TASK-01` | `test`, `lint`, `format`, and `check` tasks exist                                                | Required | `task --list-all`                            |
| `REPO-TASK-02` | Applicability of `build` and `dev` was an explicit decision, and they exist where applicable     | Required | Manual — `task --list-all` plus the recorded decision |
| `REPO-TASK-03` | `task check` runs everything CI runs                                                             | Required | Manual — Compare taskfile against workflows |
| `REPO-TASK-04` | In a monorepo, each release unit has a `taskfile.yml` at its path                                | Required | File presence per `.intentional/config.yml`  |
| `REPO-TASK-05` | Every include sets `dir:`                                                                        | Required | Root `taskfile.yml`                          |
| `REPO-TASK-06` | Include namespaces match release unit ids                                                        | Required | Compare against `.intentional/config.yml`    |
| `REPO-CI-01`   | CI is triggered on `pull_request`                                                                | Blocking | Workflow contents                            |
| `REPO-CI-02`   | Workflow-level `permissions:` is set to `{}`                                                     | Blocking | Workflow contents                            |
| `REPO-CI-03`   | Every job declares only the permissions it needs                                                 | Required | Workflow contents                            |
| `REPO-CI-04`   | Every action is pinned to a full commit SHA with a version comment                               | Blocking | Workflow contents                            |
| `REPO-CI-05`   | No workflow uses `pull_request_target`                                                           | Blocking | Workflow contents                            |
| `REPO-CI-06`   | A `concurrency` group with `cancel-in-progress` covers pull requests                             | Required | Workflow contents                            |
| `REPO-CI-07`   | Every job invokes a task rather than a raw command                                               | Required | Workflow contents                            |
| `REPO-CI-08`   | A required check validates pull request title format                                             | Required | Workflow contents and ruleset                |
| `REPO-CI-09`   | The scheduled audit workflow uses a verified read-only `AIRLOCK_TOKEN`                            | Required | Workflow contents                            |
| `REPO-CI-10`   | No workflow mutates repository settings                                                          | Required | Manual — Workflow contents |
| `REPO-CD-01`   | A repository that delivers anything has `.github/workflows/cd.yml`                               | Required | File presence                                |
| `REPO-CD-02`   | A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*` | Required | Workflow contents                            |
| `REPO-CD-03`   | A repository deploying a site or service triggers CD on push to the default branch               | Required | Workflow contents                            |
| `REPO-CD-04`   | CD sets `concurrency` with `cancel-in-progress: false`                                           | Blocking | Workflow contents                            |
| `REPO-CD-05`   | A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release             | Blocking | Manual — Dispatch inputs and their use |
| `REPO-CD-06`   | CD asserts every required publication credential is present before doing any work                | Required | Manual — Workflow contents |
| `REPO-CD-07`   | Release creation and delivery are separate workflows                                             | Required | Workflow contents                            |
| `REPO-HOOK-01` | `pre-commit` runs `format` and `lint` on staged files only                                       | Required | `.config/lefthook.yml`                       |
| `REPO-HOOK-02` | `commit-msg` validates conventional commit format                                                | Required | `.config/lefthook.yml`                       |
| `REPO-HOOK-03` | `pre-push` runs nothing or lint only                                                             | Required | `.config/lefthook.yml`                       |
| `REPO-HOOK-04` | Hooks invoke tasks rather than raw commands                                                      | Required | `.config/lefthook.yml`                       |

## Agent affordances

| Id              | Assertion                                                                                                                                 | Severity | How to check  |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------- |
| `REPO-AGENT-01` | `AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live | Required | Manual — Read |
| `REPO-AGENT-02` | `AGENTS.md` contains nothing discoverable by reading the repository                                                                       | Required | Manual — Read |
| `REPO-AGENT-03` | `AGENTS.md` does not restate the README or `CONTRIBUTING.md`                                                                              | Required | Manual — Compare |
| `REPO-AGENT-04` | `CONTRIBUTING.md` contains no command sequences beyond `task check`                                                                       | Required | Manual — Read |
| `REPO-AGENT-05` | Generated directories are marked `linguist-generated=true` in `.gitattributes`                                                            | Required | Manual — File contents |

## Documentation

| Id             | Assertion                                                                                    | Severity    | How to check                             |
| -------------- | -------------------------------------------------------------------------------------------- | ----------- | ---------------------------------------- |
| `REPO-DOCS-01` | User-facing pages sit at the top level of `docs/`                                            | Observation | Manual — Directory listing |
| `REPO-DOCS-02` | Engineering artifacts sit in `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/` | Observation | Manual — Directory listing |
| `REPO-DOCS-03` | Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field              | Observation | Manual — File inspection |
| `REPO-DOCS-04` | A tool publishing docs to `wyrd.foo` has `docs/docs.yml`                                     | Required    | Manual — File presence plus the recorded decision |
| `REPO-DOCS-05` | Schema-bound YAML artifacts follow their schema where one exists                             | Observation | Manual — schemas may resolve outside the bounded repository snapshot |

## Release

Applies only where the repository publishes a versioned artifact.

| Id            | Assertion                                                                        | Severity | How to check                              |
| ------------- | -------------------------------------------------------------------------------- | -------- | ----------------------------------------- |
| `REPO-REL-01` | `.intentional/config.yml` exists and declares release units                      | Required | File presence                             |
| `REPO-REL-02` | A `CHANGELOG.md` exists at each release unit's declared path                     | Required | Compare against `.intentional/config.yml` |
| `REPO-REL-03` | A multi-unit repository has no root aggregate changelog                          | Required | File presence                             |
| `REPO-REL-04` | Release is `workflow_dispatch` on a pinned source SHA                            | Blocking | Workflow contents                         |
| `REPO-REL-05` | The release workflow asserts the pinned SHA equals current `main`                | Blocking | Manual — Workflow contents |
| `REPO-REL-06` | The release workflow asserts a successful push-event CI run for exactly that SHA | Blocking | Manual — Workflow contents |
| `REPO-REL-07` | No workflow publishes automatically on merge                                     | Blocking | Workflow contents                         |

## Classification

| Id             | Assertion                                                      | Severity | How to check      |
| -------------- | -------------------------------------------------------------- | -------- | ----------------- |
| `REPO-PROP-03` | `.github/repo-settings.yml` declares no custom property values | Blocking | File contents     |
| `REPO-PROP-04` | No workflow writes organization custom properties              | Blocking | Workflow contents |
