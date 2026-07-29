---
name: repository-standards
description:
  What a public Wyrd Company, Flapstack, or personal repository must contain and
  how it must be configured — required files, licensing, naming, topics, git
  rulesets, taskfile verbs, CI conventions, docs layout, and release policy. Use
  when creating a new public repo, auditing an existing public repo for gaps, or
  preparing a private repo to be published. Covers the four orgs wyrd-company,
  boblangley, flapstack, and mmenm. Does not cover forks, private repos, or
  archiving.
---

# Public Repository Standards

This skill defines what conformance looks like for a **public, non-fork
repository**. It is normative: every statement is written to be mechanically
checkable so an auditing agent can turn a gap into a task without judgment
calls.

Airlock is the durable upstream for this skill. `airlock skill <directory>`
emits the complete tree carried by the installed binary. The rule ids,
statements, severities, sections, and evaluation modes in
`references/conformance.md` are generated from that binary's compiled registry;
the registry version and digest at the top of the reference identify the exact
questions it describes. This document, the topics vocabulary, platform
references, templates, and application guidance are hand-written here in
Airlock. A standalone copy in an agent skill directory is an installed working
copy, not a second authority; refresh or replace it from the Airlock release
that should govern the agent's work.

`references/check-guidance.md` is the hand-written source for practical
rule-by-rule inspection guidance. Airlock joins it to the registry projection
when generating `references/conformance.md`; it does not define or override any
registry-owned field.

## Scope

Applies to public, non-fork repositories in `wyrd-company`, `boblangley`,
`flapstack`, and `mmenm`.

Out of scope:

- **Forks.** Upstream conventions win. See the "Working in Forks" context
  instead.
- **Private repositories.** Including lab work.
- **Archiving.** A separate procedure.

The scope boundary is also a rule, and it is the one that removes every special
case:

> **Lab and speculative work stays private. A public repository meets this
> standard — if it is not going to, keep it private.**

## Modes

Three ways to run this skill. Establish which one applies before doing anything.

**Scaffold** — create a new public repository. Work top to bottom through this
document. Several rules require an explicit decision rather than a default; make
those decisions with the user, do not guess.

**Audit** — check an existing repository and raise gap tasks. Walk
`references/conformance.md` and report every failing rule. One task per
repository, not per rule, unless the user asks otherwise.

**Publish** — a private repository is becoming public. Run the audit first.
Everything must pass _before_ visibility changes, because a public repository is
public the moment it flips, including its full history.

## Reporting findings

Cite a rule by **id and statement together**, never by id alone.

```text
REPO-CI-02  Workflow-level `permissions:` is not set to `{}` in ci.yml
```

Not `REPO-CI-02 failed`. Rule numbers are for stability and comparison across
repositories, not for communication — nobody reading a task later remembers what
`REPO-CI-02` means.

## What this standard relies on

Some configuration lives outside the repository and is **neither validated nor
managed by this standard**. It is stated here as fact, because it constrains how
a repository is authored.

- **The default branch is protected.** Pull requests are required, with one
  approval. The only actor that may advance it without one is the release
  authority, and only to a validated release commit. You cannot push to it
  directly.
- **History on the default branch cannot be rewritten.** No force-push, no
  non-linear history, and nothing bypasses that — not even release automation.
- **Only squash and rebase merges exist.** History is linear and contains no
  merge commits.
- **Tags are immutable.** Nothing may move or delete one, including release
  automation. Version tags are created by release automation alone.
- **Community health files are inherited** from the owning account's `.github`
  repository. A repository carries its own copy only to differ.
- **Repository settings are applied by a reconciler**, from
  `.github/repo-settings.yml`. Changing settings in the GitHub interface is not
  a change.
- **Repositories are classified by organization custom properties.** Rulesets
  target those values.

Two constraints follow from that last point and bind the repository:

- **Custom properties are never declared by the repository.** They must not
  appear in `.github/repo-settings.yml` and no workflow may set one. Rulesets
  are targeted by these values, so a repository able to declare its own could
  edit one line and opt itself out of the protections that govern it.
- **App credentials follow a fixed naming convention.** An app id is a
  **variable** named `<CAPABILITY>_APP_ID`; its private key is a **secret**
  named `<CAPABILITY>_APP_PRIVATE_KEY`. Never name a credential after the task
  that introduced it.

> **Do not read `references/platform/` while scaffolding or auditing.** It
> documents the organization's apps, rulesets, properties, secrets, and
> environments, and is read only when that configuration is being **changed**.
> Everything a repository author needs is stated above.

## Identity

### Settings as an artifact

Repository metadata is **declared in the repository and reconciled outward**,
not set by hand in the GitHub UI and not written by an agent calling the API.

`.github/repo-settings.yml` holds the desired state. A `reconcile-settings`
workflow runs on push to the default branch, mints a token from the
`repo-settings` app, and applies the file idempotently.

```yaml
description: Intent-driven polyglot releases.
topics:
  - cli
  - rust
  - release-automation
  - versioning
merge:
  squash: true
  rebase: true
  merge_commit: false
  delete_branch_on_merge: true
features:
  wiki: false
  projects: false
  discussions: false
```

The principle is the same one that governs releases: **agents propose,
deterministic workflows dispose.** An agent produces a validated declarative
input; a pinned workflow holding the credential applies it. No agent ever holds
a write credential.

What this buys beyond credential safety:

- Description and topics stop being invisible GitHub state and become a reviewed
  artifact, with a single source of truth like everything else.
- Drift self-corrects instead of being reported. The file is the truth; GitHub
  converges on it.
- A settings change goes through pull request review like any other change.

**Reconciliation never manages visibility.** The `repo-settings` app can change
it, and an accidental reconcile that publishes a private repository is
unrecoverable. Visibility stays a deliberate manual act, and the file has no
field for it.

### Home organization

The org is part of the repository's public identity and it is stickier than it
looks. GitHub redirects the repository URL after a move, but it does not fix
published package names, npm or crates scopes, GHCR image paths, or anything
pinned downstream. Choose deliberately.

| Org            | The repository is…                            |
| -------------- | --------------------------------------------- |
| `boblangley`   | Overfit to Bob's workflow, machines, or data  |
| `wyrd-company` | Generalized enough that a stranger benefits   |
| `flapstack`    | A vendor-neutral public good, owned by no one |
| `mmenm`        | Lab work — private, therefore out of scope    |

**Graduation path.** Overfit tools live in `boblangley` and move to
`wyrd-company` when they generalize. During an audit, a `boblangley` repository
showing signs of general utility is a finding worth raising, not a violation.

### Name

- `lower-kebab-case`. Digits are fine. No underscores, no camelCase, no
  PascalCase.
- **Dotted names only when the repository is a deployable site or service and
  the name is its hostname.** `flapstack.blog` qualifies; nothing else does.
- **Match the ecosystem** where it has a naming convention of its own.
- **Family prefix** when the repository belongs to a product family, matching
  the family topic. A repository named `ahp-nats` carries the
  `agent-host-protocol` topic; the name and the topic agree.
- **Products get names, utilities get descriptions.** A repository that embodies
  an idea gets a name it can grow into. A repository that moves bits gets a name
  that says what it moves. Prefer a name.

### Description

Declared as `description` in `.github/repo-settings.yml`. It is the repository's
one-line pitch, and what appears in search results and on the org page.

- One sentence. At most 160 characters, and the meaning must survive truncation
  at ~80.
- States what it does and who it is for.
- Expands any acronym on first use.
- Personality is welcome. **Self-deprecation is not** — "a vibe coded…" tells a
  visitor the code is untrustworthy, which is a strange thing to volunteer about
  something you chose to publish.
- Agrees with the README's opening line. Disagreement between them is a defect.

### Topics

Declared as `topics` in `.github/repo-settings.yml`. Three to eight, drawn from
four facets. See `references/topics.md` for the seed vocabulary.

| Facet          | Required        | Purpose                                                    |
| -------------- | --------------- | ---------------------------------------------------------- |
| Artifact type  | Yes             | What you get — `cli`, `mcp-server`, `library`, `container` |
| Ecosystem      | Yes             | How you install or run it — `rust`, `typescript`, `go`     |
| Domain         | No              | The problem space — `ai-agents`, `release-automation`      |
| Product family | When applicable | Ties sibling repositories together across orgs             |

The vocabulary is **seeded, not closed**. Prefer an existing term. Before
coining a new one, survey what is already in use so you adopt or normalize
rather than inventing a third synonym:

```bash
gh repo list <org> --visibility public --limit 200 \
  --json repositoryTopics --jq '.[].repositoryTopics[]?.name' \
  | sort | uniq -c | sort -rn
```

When you do coin a term, add it to `references/topics.md` in the same change. An
uncontrolled vocabulary fails invisibly — nothing breaks, discovery just quietly
stops working.

Do not add an org-name topic. The org page already groups by org.

## Licensing

A public repository with no `LICENSE` is "all rights reserved" — nobody may
legally use, fork, or contribute to it. This is the highest-severity failure in
this document.

| The repository…                                         | License                      |
| ------------------------------------------------------- | ---------------------------- |
| Embodies an idea and carries Wyrd or Flapstack branding | **Apache-2.0** — the default |
| Is a spec or schema meant to be implemented verbatim    | **CC0-1.0**                  |
| Is plumbing — moves bits, no invention inside           | **MIT**                      |
| Extends another ecosystem with a compelling reason      | **Match that ecosystem**     |

Apache-2.0 is the default because it grants patents expressly, makes
contributions inbound-equals-outbound so outside pull requests need no CLA, and
states that the copyright grant conveys no trademark rights.

**Never dual-license `MIT OR Apache-2.0`.** The consumer picks, and they pick
MIT — which discards the patent grant, the contribution clarity, and the
trademark carve-out simultaneously. This is the common Rust convention and it is
wrong for these repositories.

Two consequences that are easy to miss:

- **Registry-publishing repositories declare the license in package metadata** —
  the `license` field in `package.json`, `Cargo.toml`, `pubspec.yaml`. GitHub
  shows a license tab; npm, crates.io, and pkg.go.dev do not, and read metadata
  instead.
- **Plumbing repositories state in the README that the license covers the
  packaging, not the payload.** A Homebrew tap licensed MIT does not relicense
  what it installs.

Not owning a wrapped product does not change the license choice. Your copyright
covers your adapter, not the thing it adapts. Their trademarks and API terms are
separate concerns and are unaffected by your `LICENSE`.

## Files

### Inherited from the org

The org's `.github` repository supplies these to every public repository in the
org that does not carry its own copy. Do not duplicate them per repository; add
a local copy only to _differ_.

`CODE_OF_CONDUCT.md` · `SECURITY.md` · `SUPPORT.md` · `GOVERNANCE.md` ·
`FUNDING.yml` · issue templates and `config.yml` · `PULL_REQUEST_TEMPLATE.md` ·
`profile/README.md`

Two things are **not** inherited despite the intuition:

- **Workflows.** The `.github` repository can host reusable workflows, but each
  repository must explicitly call them. Shared CI means one caller workflow per
  repository, not zero.
- **Renovate.** Configuration is per repository, extending the org preset — one
  line, but a required line. (Dependabot is not used.)

### Required in every public repository

| File                        | Notes                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `README.md`                 | See [README](#readme)                                                                                                     |
| `LICENSE`                   | Not inheritable                                                                                                           |
| `CONTRIBUTING.md`           | Per repository — build and test specifics are repository-specific                                                         |
| `.gitignore`                | Ecosystem-appropriate                                                                                                     |
| `.gitattributes`            | Line-ending normalization; marks generated paths                                                                          |
| `.editorconfig`             |                                                                                                                           |
| `taskfile.yml`              | Lowercase filename. See [Automation](#automation)                                                                         |
| `.github/workflows/`        | `ci.yml`, `reconcile-settings.yml`, and `cd.yml` where the repo delivers. See [Workflow vocabulary](#workflow-vocabulary) |
| `.github/renovate.json`     | Extends the org preset                                                                                                    |
| `.github/repo-settings.yml` | Declared repository metadata. See [Settings as an artifact](#settings-as-an-artifact)                                     |
| `.config/lefthook.yml`      |                                                                                                                           |
| `.devcontainer/`            | Every repository — an outside contributor cannot reconstruct the build environment                                        |
| `AGENTS.md`                 | See [Agent affordances](#agent-affordances)                                                                               |
| `CLAUDE.md`                 | A symlink to `AGENTS.md`                                                                                                  |

### Required under conditions

| File                      | Condition                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| `CHANGELOG.md`            | One at each release unit's declared path                                                     |
| `.intentional/config.yml` | The repository publishes a versioned artifact                                                |
| `docs/docs.yml`           | The repository is a tool publishing docs to `wyrd.foo` — an explicit per-repository decision |

### Deliberately not required

**`CODEOWNERS`.** It exists to route review across a team. With a solo
maintainer it assigns you to review your own pull requests. Every required file
should mean something.

**No agent harness configuration.** No `.claude/`, no `.cursor/`, no equivalent.
`AGENTS.md` is the only agent-facing file. Skills that _ship as product_ are
source code and belong in the repository like any other source; skills that
configure how you work do not.

## README

The README is the product page and the only file most visitors read. It is also
rendered on npm, crates.io, and pkg.go.dev, where GitHub's chrome does not
exist.

### Required

1. Title and a one-line statement of what it is, agreeing with the GitHub
   description
2. Badges
3. Installation — every supported channel
4. Quickstart or usage — at least one real, runnable example

### Encouraged

- Logo in SVG format
- Animated demo for anything with a user interface, CLI or app. **Commit the
  `.tape`** so the demo regenerates instead of rotting into a stale hand-made
  artifact.
- Why it exists, the problem, or features — appropriate to most repositories

### Conditional

- Prerequisites, _only_ when non-obvious — an unbundled runtime, an external
  service, an API key. A statically linked binary installed from the tap has
  none, and "Prerequisites: none" is noise.
- Configuration — inline for a simple tool, in `docs/` otherwise

### Absent

- No license section. GitHub surfaces `LICENSE` as a header tab. Package
  metadata covers the registries.
- No contributing section. GitHub surfaces `CONTRIBUTING.md` as a header tab.

## Git configuration

### Rulesets

Branch protection is applied **org-wide**, targeting the default branch of
`visibility:public` repositories, not configured per repository.

- Pull requests required on the default branch.
- **No bypass**, including for admins. The only exception is a designated
  release GitHub App.
- A second ruleset restricts ref updates to the write role and org admins.

Effective rulesets are readable at repository scope — see
[Protected configuration](#what-this-standard-relies-on) for what an agent can
and cannot verify.

### Merging

Declared in `.github/repo-settings.yml` and reconciled; the ruleset enforces the
same constraints independently.

| Setting                      | Value                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| Default branch               | `main`                                                                                                  |
| Merge commits                | Disabled                                                                                                |
| Squash merge                 | Enabled — the default                                                                                   |
| Rebase merge                 | Enabled — permitted where a release flow depends on preserved commit messages or per-commit granularity |
| Auto-delete head branch      | Enabled                                                                                                 |
| Wikis, Projects, Discussions | Off unless deliberately used                                                                            |

Squash merge means **the commit that lands on `main` is the pull request
title**. The title is therefore load-bearing history, which is why it carries a
required conventional-commit check.

### Tags and releases

- Single release unit: `{version}`. Multiple: `@scope/name@version`.
- **No `v` prefix.**
- Releases are produced by automation. Never create one by hand.

## Automation

### taskfile.yml

`taskfile.yml`, lowercase. Task discovers it.

The value is not that a taskfile exists — it is that **the same verb means the
same thing in every repository**, so anyone can walk in and work without reading
anything.

| Verb        | Meaning                                                    |
| ----------- | ---------------------------------------------------------- |
| _(default)_ | List available tasks                                       |
| `build`     | Produce the artifact                                       |
| `test`      | Run the full test suite                                    |
| `lint`      | Static analysis, non-mutating                              |
| `format`    | Apply formatting, mutating                                 |
| `check`     | Everything CI runs — the one command to run before pushing |
| `dev`       | Run locally with hot reload or watch                       |

`test`, `lint`, `format`, and `check` are required everywhere. Every repository
has something to validate, even if it is only linting YAML and Markdown.

`build` and `dev` are required **where applicable**, and applicability is an
**explicit decision made when this skill runs** — state which verbs apply and
why. Absence is a decision, not an omission.

### Monorepo composition

- Root `taskfile.yml` carries the universal verbs and fans out to includes.
- Each release unit has its own `taskfile.yml` at its path.
- **Every include sets `dir:`.** By default an included task runs in the _root_
  directory, not its own. This is silent — tests run from the wrong working
  directory and mostly still pass, until they do not.
- **The include namespace is the release unit id** from
  `.intentional/config.yml`, so `task design-system:test` works and releases,
  changelogs, and tasks share one naming axis.

```yaml
version: "3"
includes:
  design-system:
    taskfile: ./packages/design-system
    dir: ./packages/design-system
```

### Workflow vocabulary

A workflow name states what the workflow is for, and the same name means the
same thing in every repository.

| Workflow                 | Purpose                            | Trigger                                                            |
| ------------------------ | ---------------------------------- | ------------------------------------------------------------------ |
| `ci.yml`                 | Validate a change                  | `pull_request`, and push to the default branch                     |
| `cd.yml`                 | Deliver                            | Whatever "delivered" means for this repository — see below         |
| `release.yml`            | Create the release commit and tag  | `workflow_dispatch` only, on a pinned SHA. Release-tier repos only |
| `reconcile-settings.yml` | Apply declared repository settings | Push to the default branch, path-filtered                          |

**`release.yml` creates the tag; `cd.yml` reacts to it.** They are separate
because they need different things: the release act needs an authority
credential and a human dispatch, while delivery needs registry credentials and
must be re-runnable for recovery without re-releasing anything.

#### `cd.yml`

The trigger follows from what the repository delivers:

| The repository delivers    | Trigger                                        |
| -------------------------- | ---------------------------------------------- |
| A versioned artifact       | `push` on tags matching `[0-9]*.[0-9]*.[0-9]*` |
| A deployed site or service | `push` on the default branch                   |

Both forms also accept `workflow_dispatch` — **for recovery, not for
releasing.** Where the repository publishes, the dispatch input names an
existing immutable tag to re-deliver. A dispatch must never be able to create a
release that did not already exist.

`cd.yml` is required wherever a repository delivers anything. A repository that
delivers nothing does not have one.

**`concurrency` with `cancel-in-progress: false`.** This is the opposite of CI
and the difference matters: cancelling a publish mid-flight can leave a registry
half-updated, with some packages at the new version and some not. A superseded
CI run is waste; a superseded delivery is damage.

**Fail on missing credentials before doing any work.** A preflight job that
asserts every required publication credential is non-empty turns "we published
three of five packages then died" into "we stopped before starting."

### CI

Public repositories run workflows against untrusted contributor code. These
conventions are security posture, not style.

- **`permissions: {}` at workflow level**, elevated per job to the minimum
  needed.
- **Pin every action to a full commit SHA** with a version comment
  (`uses: actions/checkout@34e1148… # v4`). A tag is mutable. Renovate updates
  pinned SHAs.
- **`concurrency` with `cancel-in-progress`** on pull requests.
- **`pull_request`, never `pull_request_target`.** `pull_request_target` runs
  fork code with secrets and write access — the most exploited GitHub Actions
  vulnerability.
- **Decomposed jobs**, one per concern, so a failure is legible on the pull
  request.
- **Every job invokes a task, never a raw command.** `task check` is the local
  equivalent; neither definition may drift from the other.
- **A required check on pull request title format**, because squash merge makes
  the title the commit message.

### Hooks

`.config/lefthook.yml`. Hooks invoke tasks, never raw commands.

| Hook         | Runs                                      |
| ------------ | ----------------------------------------- |
| `pre-commit` | `format` and `lint`, on staged files only |
| `commit-msg` | Conventional commit format                |
| `pre-push`   | Nothing, or lint only                     |

`pre-push` stays cheap deliberately. A pre-push hook that runs the full suite
teaches you to pass `--no-verify`, which silently disables the pre-commit hooks
too. CI is the gate; hooks are fast feedback.

## Agent affordances

`AGENTS.md` is required. `CLAUDE.md` is a symlink to it.

One source of truth per kind of knowledge. These files point at each other
rather than repeating:

| File              | Owns                                                        | Never contains                                  |
| ----------------- | ----------------------------------------------------------- | ----------------------------------------------- |
| `taskfile.yml`    | How anything runs                                           | —                                               |
| `CONTRIBUTING.md` | Human process — how to propose a change, what gets accepted | Command sequences beyond `task check`           |
| `AGENTS.md`       | The delta an agent gets wrong without being told            | Anything discoverable by reading the repository |

`AGENTS.md` structure, deliberately short:

1. What this repository is — one line
2. Commands — by reference to `task` verbs
3. Repository-specific conventions an agent would otherwise violate
4. What not to touch — generated output, vendored code, lockfiles
5. Where documentation lives

> **If a statement in `AGENTS.md` is discoverable by reading the repository,
> delete it.**

The failure mode this prevents is the 400-line `AGENTS.md` that restates the
README, drifts within a month, and then actively misleads.

Mark generated directories in `.gitattributes`:

```text
generated/** linguist-generated=true
```

This collapses them in pull request diffs and stops humans and agents from
reviewing machine output as though it were authored.

## Documentation

```text
docs/
  docs.yml              product descriptor — feeds wyrd.foo
  overview.md           user-facing
  install.md
  usage.md
  config.md
  decisions/            engineering artifacts
  technical-designs/
  spikes/
```

User-facing pages sit at the top level; engineering artifacts sit in typed
subdirectories. Both are public, and that is deliberate — published decision
records are the clearest signal to a prospective contributor that a project is
seriously maintained.

An artifact's id is its filename stem: a lower-kebab slug, no type prefix, no
`id:` field.

`docs/docs.yml` describes the product for the site — name, tagline, blurb,
category, language, status, repository URL, install commands per channel, demo
asset. It is consumed by a publish action that projects `docs/` into the site's
content tap on release.

This is not the only documentation pipeline in use. A product family may instead
dispatch documentation data to its own site, with receipt and staleness checking
on the far side. Do not assume `docs/docs.yml` where a repository already
participates in such a pipeline; read the repository's own documentation first.

`terms/` is not required. Add one only where the repository defines vocabulary
others must use — a spec, a protocol, a design system.

**Schema-bound YAML artifacts are current practice, not yet a gate.** Refinery
is not live. Follow the schema where one exists; during an audit, report a
missing decision record as an observation rather than a violation.

## Release

Applies to repositories that publish a versioned artifact. A deployed site that
nobody pins a version of does not need any of this.

- **Intentional is the version authority.** `.intentional/config.yml` declares
  release units.
- **A `CHANGELOG.md` lives at each release unit's declared path.** A single unit
  at `.` means one changelog at the repository root. Multiple units mean one per
  unit path, and **no root aggregate** — a derived view that will drift.
- **Release is manual and evidence-gated.** `workflow_dispatch` on a pinned
  source SHA, which must equal current `main` and must have a proven successful
  push-event CI run for exactly that SHA.

Never publish automatically on merge. Beyond making every release a deliberate
act against a commit that has already proven itself, it is a supply-chain
control: an attacker who lands a commit still cannot trigger a publish.

## References

- `references/conformance.md` — the numbered checklist; the audit surface
- `references/topics.md` — seed topic vocabulary by facet
- `references/templates/` — starting files for the mechanical requirements
- `references/platform/` — organization apps, rulesets, properties, secrets, and
  environments. **Read only when changing that configuration**, never while
  scaffolding or auditing a repository.
