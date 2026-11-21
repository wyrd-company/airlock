# Working in this repository

Airlock is a read-only auditor. Two crates: `airlock-core` holds the compiled
rules, configuration resolution, report model, and GitHub client.
`airlock-cli` is a thin front end that parses arguments and renders.
Logic belongs in core — if a command handler grows a decision, that decision
is in the wrong crate.

The audit human output includes each gap's fix and reason. The JSON agent work
list is the machine projection; there is no separate plan command or stored
plan. Airlock re-observes before acting.

Run `task check` before pushing; it is what CI runs. Everything else is in
`taskfile.yml`.

## Constraints that are not negotiable

**The audit never writes.** `airlock audit` and every audit surface hold no
mutating endpoint and refuse any credential that could write. Central mode's
only requests that are not reads mint its own installation token and revoke
it; neither changes a repository or an organization. The interactive
align session alone may apply settings-level fixes — under an
operator's device-flow grant held only in memory. It may author the initial
commit of a repository it is creating. It never modifies an existing
repository's files.
`airlock skill` emits the embedded skill into a local directory and uses no
credential.

**The binary never shells out.** No `git`, no `gh`, no subprocess at all from
`airlock` or anything it depends on. Airlock speaks the GitHub REST API
directly. The same holds for the WebAssembly module and the action's bundled
JavaScript that loads it: every request goes through the host's `fetch`, and
nothing starts a process. No workflow receives automated settings-write authority.

**No ambient credentials.** `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential
store, and git credential helpers are off limits as sources and must not be
mentioned as fallbacks in error messages. Suggesting them defeats the point of
refusing write access. The run's own token reaches Airlock only when a
workflow passes it explicitly, as the Action's `token` input in repository
mode. `AIRLOCK_RUN_TOKEN` is not a credential source, and the action sets it
from `github.token` in its own step's `env`, never from an input: repository
mode admits an installation token only when it equals that value, and sends
nothing with it.

**A token whose permissions cannot be enumerated is refused.** Unverifiable is
not a warning path. Adding a token prefix means adding the introspection that
proves it read-only, or refusing it. An installation token is enumerated in
two places only: repository mode reads the run token's grant from the job's
declared permissions (`crates/core/src/workflow_token.rs`), and central mode
reads its own minted token's grant from the minting response
(`crates/core/src/central.rs`). Every other surface refuses one. Repository
mode first places the token by its `ghs_15368_` form and GitHub's answer to
`GET /installation/repositories`; it fails closed when the form changes.

**Rule identity is compiled in.** Rule ids, statements, and default severities
live in per-rule modules under `crates/core/src/rules/`, assembled by
`crates/core/src/rules.rs`, not in configuration files. Organization
configuration parameterises and re-grades rules through reasoned exceptions;
it cannot define a rule or express a predicate. A check is the compiled
procedure that evaluates a rule. A requirement beyond those procedures needs
a new rule.

**A rule that is not implemented is registered, not omitted.** Silent absence
is the failure mode that makes an audit tool untrustworthy.

## Vocabulary

A rule states a requirement; its check evaluates it. A gap is an evaluated
rule the repository does not meet. A fix closes a gap; its fix kind identifies
Airlock, an agent, or an operator as the author. An exception changes a rule's
parameters or severity with a reason. A waiver is a rule with effective severity
`none`, from a reasoned exception or absent required configuration. The report
lists its reason and does not run its check. Configuration never selects rules.
Definitions live in `docs/terms/`.

## What not to touch

`.github/airlock.yml` is the source of truth for repository metadata and
is applied by an operator through Airlock's terminal interface. `airlock
align-files` cannot apply settings. Editing settings in the GitHub web
interface is drift, not a change; the scheduled read-only audit detects the
discrepancy.

Version numbers are computed at release time from `.intentional/config.yml`. Do
not hand-edit the version in `Cargo.toml` or write a release entry in
`CHANGELOG.md`.

Action pins are full commit SHAs with a version comment. Renovate moves them.
Do not replace a pin with a tag.

## Where things live

The per-rule modules under `crates/core/src/rules/` are the source of
truth for rule ids, statements, severities, sections, evaluation modes,
parameter defaults, fix kinds, lifecycle metadata, and inspection guidance.
`airlock skill` generates both `references/conformance.md` and
`references/check-guidance.md` from those modules. The embedded skill's
workflow guidance and supporting material are hand-written.

`docs/examples/` holds organization and repository `.github/airlock.yml`
examples. The organization file governs reasoned exceptions; the repository
file holds declarations and exception requests. Both accept an Airlock
generation through `version`. Configuration loading and integration tests
validate these shapes against the compiled rules.

`action.yml` defines the adopter-facing action, repository mode only: a
composite that sets up a pinned Node and runs the committed `dist/`. It stays
a composite so the run's own token comes from its step's `env`, which a
caller cannot set; do not turn it into an input. Its audit step hands Node
an allowlisted environment (`action/step.sh`): a new variable the engine
needs goes on that list, never a blocklist. `task action:build` builds
`dist/` from `action/src/` and the module; commit `dist/` with any change
that reaches it, because CI fails when it differs from the source. The action's
decisions about its inputs are in `action/src/main.mjs`; every check on the
token is in the engine. See `docs/action.md`.
`crates/core/src/central_audit.rs` audits every repository central mode
reaches into one report.

Wider design context lives in memory and in the kanban task, not here.
