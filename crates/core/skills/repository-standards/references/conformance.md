# Conformance Checklist

This reference is generated from Airlock rules **0.6.0**
(`sha256:dc1a3e65756ace13c57a29a52541485edbdc2042fd2233237b8367a85ed286ce`).
The rules are authoritative for every rule id, statement, default
severity, section, and declared gates in this document.

**Always cite a rule by id and statement together.** A rule id alone
is not a meaningful finding.

## Severity

| Level | Meaning |
| --- | --- |
| **Blocking** | Evaluate, report Gaps, and fail the Action on a Gap |
| **Advisory** | Evaluate and report Gaps without failing the Action |
| **None** | Do not evaluate; list the waiver and its reason |

## Identity

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-ORG-01` | The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good | Advisory | Compiled check with an unbuilt gate | Judgment | seeded |
| `REPO-ORG-02` | A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company` | Advisory | Compiled check with an unbuilt gate | Judgment | seeded |
| `REPO-NAME-01` | The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase | Advisory | Compiled check | Repository name | seeded |
| `REPO-NAME-02` | A dotted name is used only where the repository is a deployable site and the name is its hostname | Advisory | Compiled check with an unbuilt gate | Repository name | seeded |
| `REPO-NAME-03` | A repository in a product family carries the family prefix | Advisory | Compiled check with an unbuilt gate | Repository name | seeded |
| `REPO-NAME-04` | The family prefix and the family topic agree | Advisory | Compiled check with an unbuilt gate | Name vs topics | seeded |
| `REPO-META-01` | `.github/repo-settings.yml` declares a description | Blocking | Compiled check | File contents | seeded |
| `REPO-META-02` | The description is one sentence, at most 160 characters, and survives truncation at ~80 | Advisory | Compiled check with an unbuilt gate | File contents | seeded |
| `REPO-META-03` | The description expands any acronym on first use | Advisory | Compiled check with an unbuilt gate | Read it | seeded |
| `REPO-META-04` | The description contains no self-deprecation | Advisory | Compiled check with an unbuilt gate | Read it | seeded |
| `REPO-META-05` | The description agrees with the README's opening line | Advisory | Compiled check with an unbuilt gate | Compare | seeded |
| `REPO-META-06` | Between three and eight topics are declared | Advisory | Compiled check | File contents | seeded |
| `REPO-META-07` | Topics include at least one artifact-type and one ecosystem term | Advisory | Compiled check | Compare against `topics.md` | seeded |
| `REPO-META-08` | A repository in a product family carries the family topic | Advisory | Compiled check with an unbuilt gate | Compare against `topics.md` | seeded |
| `REPO-META-09` | Any topic not in `topics.md` has been added to it | Advisory | Compiled check | Compare against `topics.md` | seeded |
| `REPO-META-10` | No org-name topic is declared | Advisory | Compiled check | File contents | seeded |
| `REPO-META-11` | The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted | Advisory | Compiled check | File contents | seeded |
| `REPO-META-12` | `.github/repo-settings.yml` declares no `visibility` field | Blocking | Compiled check | File contents | seeded |
| `REPO-META-13` | Live GitHub metadata matches the declared file | Advisory | Compiled check | `gh repo view` vs file — drift means reconciliation is not running | seeded |

## Licensing

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-LIC-01` | A `LICENSE` file exists | Blocking | Compiled check | File presence | seeded |
| `REPO-LIC-02` | The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license | Advisory | Compiled check with an unbuilt gate | Judgment against the category table | seeded |
| `REPO-LIC-03` | The repository is not dual-licensed `MIT OR Apache-2.0` | Blocking | Compiled check | `LICENSE`, package metadata | seeded |
| `REPO-LIC-04` | A repository publishing to a registry declares the license in package metadata | Advisory | Compiled check | `package.json`, `Cargo.toml`, `pubspec.yaml` | seeded |
| `REPO-LIC-05` | A plumbing repository's README states that the license covers packaging, not payload | Advisory | Compiled check with an unbuilt gate | Read the README | seeded |
| `REPO-LIC-06` | A non-default license choice has a stated reason in the README or a decision record | Advisory | Compiled check with an unbuilt gate | Read | seeded |

## Files

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-FILE-01` | `README.md` exists | Blocking | Compiled check | File presence | seeded |
| `REPO-FILE-02` | `CONTRIBUTING.md` exists in the repository, not only at org level | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-03` | `.gitignore` exists and is ecosystem-appropriate | Advisory | Compiled check with an unbuilt gate | File presence | seeded |
| `REPO-FILE-04` | `.gitattributes` exists and normalizes line endings | Advisory | Compiled check | File contents | seeded |
| `REPO-FILE-05` | `.editorconfig` exists | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-06` | `taskfile.yml` exists, lowercase | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-07` | `.github/workflows/` contains at least a CI workflow triggered on pull request | Blocking | Compiled check | File presence | seeded |
| `REPO-FILE-08` | `.github/renovate.json` exists and extends the org preset | Advisory | Compiled check | File contents | seeded |
| `REPO-FILE-16` | `.github/repo-settings.yml` exists | Blocking | Compiled check | File presence | seeded |
| `REPO-FILE-17` | `.github/workflows/audit.yml` exists and triggers on a schedule and on demand | Blocking | Compiled check | File contents | seeded |
| `REPO-FILE-09` | `.config/lefthook.yml` exists | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-10` | `.devcontainer/` exists | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-11` | `AGENTS.md` exists | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-12` | `CLAUDE.md` exists and is a symlink to `AGENTS.md` | Advisory | Compiled check | `git ls-files -s CLAUDE.md` — mode `120000` | seeded |
| `REPO-FILE-13` | No agent harness configuration is committed — no `.claude/`, `.cursor/`, or equivalent | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-14` | No `CODEOWNERS` file is present | Advisory | Compiled check | File presence | seeded |
| `REPO-FILE-15` | Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs | Advisory | Compiled check with an unbuilt gate | Compare against the org `.github` repository | seeded |

## README

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-README-01` | Opens with a title and a one-line statement of what it is | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-02` | Badges are present | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-03` | An installation section covers every supported channel | Blocking | Compiled check with an unbuilt gate | Compare against published channels | seeded |
| `REPO-README-04` | A quickstart or usage section contains at least one real, runnable example | Blocking | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-05` | A repository with a user interface has an animated demo | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-06` | Where a demo exists, its `.tape` source is committed | Advisory | Compiled check | File presence | seeded |
| `REPO-README-07` | Prerequisites appear only where non-obvious | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-08` | No license section | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-README-09` | No contributing section | Advisory | Compiled check with an unbuilt gate | Read | seeded |

## Git configuration

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-GIT-01` | The default branch is `main` | Advisory | Compiled check | `gh repo view --json defaultBranchRef` | seeded |
| `REPO-GIT-02` | The repository is covered by organization-sourced rulesets on its default branch | Blocking | Compiled check | `gh api repos/{o}/{r}/rulesets?includes_parents=true` | seeded |
| `REPO-GIT-03` | Those rulesets require pull requests, allow only squash and rebase, and require linear history | Blocking | Compiled check | `gh api repos/{o}/{r}/rules/branches/main` | seeded |
| `REPO-GIT-13` | A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY` | Advisory | Compiled check | Workflow source | seeded |
| `REPO-GIT-14` | No secret or variable is named after the task that introduced it | Advisory | Compiled check with an unbuilt gate | Workflow source | seeded |
| `REPO-GIT-15` | The repository has ended seeding with an Intentional baseline tag | Advisory | Compiled check | Captured Intentional tag records and Git ancestry | seeded |
| `REPO-GIT-04` | Merge commits are disabled | Advisory | Compiled check | `gh repo view --json mergeCommitAllowed` | seeded |
| `REPO-GIT-05` | Squash merge is enabled | Advisory | Compiled check | `gh repo view --json squashMergeAllowed` | seeded |
| `REPO-GIT-06` | Auto-delete head branch on merge is enabled | Advisory | Compiled check | `gh repo view --json deleteBranchOnMerge` | seeded |
| `REPO-GIT-07` | Wikis, Projects, and Discussions are off unless deliberately used | Advisory | Compiled check with an unbuilt gate | `gh repo view` | seeded |
| `REPO-GIT-08` | Tags carry no `v` prefix | Advisory | Compiled check | `git tag` | seeded |
| `REPO-GIT-09` | Multi-release-unit tags use `@scope/name@version` | Advisory | Compiled check | `git tag` | seeded |
| `REPO-GIT-10` | History contains no merge commits | Advisory | Compiled check | `git log --merges` | seeded |

## Automation

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-TASK-01` | `test`, `lint`, `format`, and `check` tasks exist | Advisory | Compiled check | `task --list-all` | seeded |
| `REPO-TASK-02` | of `build` and `dev` was an explicit decision, and they exist where applicable | Advisory | Compiled check with an unbuilt gate | `task --list-all` plus the recorded decision | seeded |
| `REPO-TASK-03` | `task check` runs everything CI runs | Advisory | Compiled check with an unbuilt gate | Compare taskfile against workflows | seeded |
| `REPO-TASK-04` | In a monorepo, each release unit has a `taskfile.yml` at its path | Advisory | Compiled check | File presence per `.intentional/config.yml` | seeded |
| `REPO-TASK-05` | Every include sets `dir:` | Advisory | Compiled check | Root `taskfile.yml` | seeded |
| `REPO-TASK-06` | Include namespaces match release unit ids | Advisory | Compiled check | Compare against `.intentional/config.yml` | seeded |
| `REPO-CI-01` | CI is triggered on `pull_request` | Blocking | Compiled check | Workflow contents | seeded |
| `REPO-CI-02` | Workflow-level `permissions:` is set to `{}` | Blocking | Compiled check | Workflow contents | seeded |
| `REPO-CI-03` | Every job declares only the permissions it needs | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CI-04` | Every action is pinned to a full commit SHA with a version comment | Blocking | Compiled check | Workflow contents | seeded |
| `REPO-CI-05` | No workflow uses `pull_request_target` | Blocking | Compiled check | Workflow contents | seeded |
| `REPO-CI-06` | A `concurrency` group with `cancel-in-progress` covers pull requests | Advisory | Compiled check | Workflow contents | seeded |
| `REPO-CI-07` | Every job invokes a task rather than a raw command | Advisory | Compiled check | Workflow contents | seeded |
| `REPO-CI-08` | A required check validates pull request title format | Advisory | Compiled check with an unbuilt gate | Workflow contents and ruleset | seeded |
| `REPO-CI-09` | The scheduled audit workflow supplies `secrets.AIRLOCK_TOKEN` to the Airlock audit action | Advisory | Compiled check | Workflow contents and repository identity | seeded |
| `REPO-CI-10` | No workflow mutates repository settings | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CD-01` | A repository that delivers anything has `.github/workflows/cd.yml` | Advisory | Compiled check with an unbuilt gate | File presence | seeded |
| `REPO-CD-02` | A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*` | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CD-03` | A repository deploying a site or service triggers CD on push to the default branch | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CD-04` | CD sets `concurrency` with `cancel-in-progress: false` | Blocking | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CD-05` | A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release | Blocking | Compiled check with an unbuilt gate | Dispatch inputs and their use | seeded |
| `REPO-CD-06` | CD asserts every required publication credential is present before doing any work | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-CD-07` | Release creation and delivery are separate workflows | Advisory | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-HOOK-01` | `pre-commit` runs `format` and `lint` on staged files only | Advisory | Compiled check with an unbuilt gate | `.config/lefthook.yml` | seeded |
| `REPO-HOOK-02` | `commit-msg` validates conventional commit format | Advisory | Compiled check with an unbuilt gate | `.config/lefthook.yml` | seeded |
| `REPO-HOOK-03` | `pre-push` runs nothing or lint only | Advisory | Compiled check | `.config/lefthook.yml` | seeded |
| `REPO-HOOK-04` | Hooks invoke tasks rather than raw commands | Advisory | Compiled check | `.config/lefthook.yml` | seeded |

## Agent affordances

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-AGENT-01` | `AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-AGENT-02` | `AGENTS.md` contains nothing discoverable by reading the repository | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-AGENT-03` | `AGENTS.md` does not restate the README or `CONTRIBUTING.md` | Advisory | Compiled check with an unbuilt gate | Compare | seeded |
| `REPO-AGENT-04` | `CONTRIBUTING.md` contains no command sequences beyond `task check` | Advisory | Compiled check with an unbuilt gate | Read | seeded |
| `REPO-AGENT-05` | Generated directories are marked `linguist-generated=true` in `.gitattributes` | Advisory | Compiled check with an unbuilt gate | File contents | seeded |

## Documentation

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-DOCS-01` | User-facing pages sit at the top level of `docs/` | Advisory | Compiled check with an unbuilt gate | Directory listing | seeded |
| `REPO-DOCS-02` | Engineering artifacts sit in `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/` | Advisory | Compiled check with an unbuilt gate | Directory listing | seeded |
| `REPO-DOCS-03` | Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field | Advisory | Compiled check with an unbuilt gate | File inspection | seeded |
| `REPO-DOCS-04` | A tool publishing docs to `wyrd.foo` has `docs/docs.yml` | Advisory | Compiled check with an unbuilt gate | File presence plus the recorded decision | seeded |
| `REPO-DOCS-05` | Schema-bound YAML artifacts follow their schema where one exists | Advisory | Compiled check with an unbuilt gate | schemas may resolve outside the bounded repository snapshot | seeded |

## Release

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-REL-01` | `.intentional/config.yml` exists and declares release units | Advisory | Compiled check | File presence | seeded |
| `REPO-REL-02` | A `CHANGELOG.md` exists at each release unit's declared path | Advisory | Compiled check | Compare against `.intentional/config.yml` | seeded |
| `REPO-REL-03` | A multi-unit repository has no root aggregate changelog | Advisory | Compiled check | File presence | seeded |
| `REPO-REL-04` | Release is `workflow_dispatch` on a pinned source SHA | Blocking | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-REL-05` | The release workflow asserts the pinned SHA equals current `main` | Blocking | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-REL-06` | The release workflow asserts a successful push-event CI run for exactly that SHA | Blocking | Compiled check with an unbuilt gate | Workflow contents | seeded |
| `REPO-REL-07` | No workflow publishes automatically on merge | Blocking | Compiled check | Workflow contents | seeded |
| `REPO-REL-08` | Every release of a Release Unit whose release-record policy is required has a release record on its primary tag | Advisory | Compiled check | Read the committed Release Model and primary annotated tag records, then compare published GitHub Releases. Fix release-model-missing, release-model-not-a-file, release-model-unreadable, and release-model-schema-not-supported by running intentional model with a supported producer and committing .intentional/release-model.json (agent reasoning). Fix release-record-missing by publishing a GitHub Release on the missing primary tag (operator). Routed needs-github-api requires a credentialed API-tree audit or Action. Truncated listings and API failures require a complete rerun; they are run errors, not Gaps. | released |
| `REPO-TPL-01` | The repository applies each template the organization expects, at an accepted revision and with only accepted parts | Blocking | Compiled check | Read the configured applied record as JSON at the audited revision. For record-missing, record-not-a-file, record-unreadable, record-schema-not-supported, application-missing, revision-not-accepted, revision-not-git or part-not-accepted, apply, update or baseline with Toha, select accepted parts, and commit the result. Organization exceptions alone configure templates and record-path; allow-override: false. | building |

## Classification

| Id | Assertion | Severity | Compiled check | Guidance | From maturity |
| --- | --- | --- | --- | --- | --- |
| `REPO-PROP-03` | `.github/repo-settings.yml` declares no custom property values | Blocking | Compiled check | File contents | seeded |
| `REPO-PROP-04` | No workflow writes organization custom properties | Blocking | Compiled check | Workflow contents | seeded |
