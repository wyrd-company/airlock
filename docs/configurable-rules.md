---
relationships:
  references:
    - rule
    - config-source
---

# Configurable rules core API

`airlock_core::configurable` evaluates configuration-defined rules without a
hosted service. Callers supply configuration snapshots, observed maturity,
resolved repository commits, a read-only probe provider and an evaluation
registry. `audit` returns a serializable report. The CLI, Action and agent work
list retain their existing audit route until integration is selected.

## Configuration snapshots

`ConfigSnapshot::load` uses the bounded YAML loader, rejects duplicate keys and
retains the configuration repository, path and resolved commit. `read_at` reads
a supplied full hexadecimal commit OID through the existing GitHub client.
The low-level API accepts 40 or 64 hex digits and rejects branch names, tags,
abbreviated OIDs and whitespace. Callers resolve an allowed ref once before
loading its bytes or calling `read_at`; loading, probes and audit never
re-resolve a ref. The caller must supply bytes from the named commit when using
`load`. The API validates OID syntax, not remote object existence without a read.
Accepting a 64-digit OID does not establish that GitHub supports that hash
format; the backend reports an unsupported or missing object as a read error.
It returns explicit absence or a snapshot, and reports unreadable or truncated
input as an error. Callers can change the path; `DEFAULT_CONFIG_PATH` is
`.github/airlock.yml`. Organization configuration has `rules`,
`assignments` and optional `repositories`. Repository configuration has `rules`.
An invalid configuration envelope returns an error. Rule bodies are decoded
individually so one invalid body does not stop its siblings.

Rules name a statement, probes, conditions and severity. Every condition names a
probe alias, a JSON Pointer, an evaluation type and a setting with `floor` and
`value`. Conditions are all-of. Assignments use the same observations and
conditions, but reference rule ids instead of defining settings for rules. An
empty assignment condition list is an explicit catch-all.

Severity is either one floor/value pair or four pairs keyed by `seeded`,
`building`, `released` and `stable`. All four rungs must be present in a schedule.
The observed rung selects the pair. A setting floor must be demonstrably no
stricter than its value under its evaluation type. Equality and glob conditions
use identical floor/value inputs; ordered comparisons and required sets can
have different inputs.

Organization-owned repository overrides appear under
`repositories: { account/repository: { rule-id: rule } }`. A replacement needs a
nonblank reason. A bad replacement is reported as invalid while the original
organization instance still runs. Overrides apply to active rule ids. After a
repository matches an assignment,
its local rule definitions also activate ids. An organization definition and
its repository override for a same-id local definition both apply, even if no
matching assignment references that id. With no matching assignment, no rules
or overrides run.

## Observations and evaluations

The probe provider publishes input and output JSON Schemas. The engine checks
request inputs before observation and checks returned outputs before use.
Schema processing is offline. Probes run only for assignment conditions and
active rule conditions. Waived instances do not observe their rule probes.
The implementation reuses exact same-input observations within one repository
in one run; it does not cache between runs.

The GitHub adapter provides `file-content` (input `path`), `repository`, `topics`
and `custom-properties` (empty inputs). File observations use the existing Git
tree and blob API client at the resolved commit. The adapter does not follow
symlinks. A missing entry in a truncated tree is an observation failure, not
absence. Existing tree, blob and aggregate byte budgets apply per repository target.
Selecting a different repository or commit clears the prior tree and resets the
byte counter; one repository cannot consume another repository's budget. An undisclosed
metadata field is omitted; selecting it is not evaluated. Archive and primary
language facts have no adapter in this increment.

Built-in evaluations are `equal`, `minimum`, `maximum`, `contains-all` and
`glob`. Selection uses JSON Pointer. A missing selected field is not evaluated.
Ordered comparisons accept JSON integers and preserve integer ordering.
Non-integer numbers need another evaluation type. Name globs use `globset`.
Evaluations are independent of probe types. Batch-capable evaluators receive one
shared probe output and an ordered list of selections and expected values.
Answers return in that order. A wrong answer count fails the whole group as
not evaluated. Assignment evaluation precedes rule evaluation so rule probes
remain demand-driven.

## Hierarchy and results

Each assigned organization rule runs once regardless of how many assignments
reference it. Repository rules run only after a repository matches an
assignment. A repository with no matching assignment has no rules or findings;
its name appears in `unassigned_repositories`. An undecided assignment appears
with `matched: null` and a diagnostic. Uncertainty never establishes unassigned.

Organization and repository definitions of the same id both run. A nonblank
repository reason switches the organization instance to floor mode. The
repository instance runs its own value. Without a reason, the organization
value remains enforced. A weaker repository setting produces a warning.
A structurally incomparable replacement produces a conservative replacement
warning; the engine does not attempt conflict detection.

A combined rule passes only if both instances pass. Its severity is the highest
severity among failing instances, or the highest instance severity when all
pass. Invalid rule instances use blocking severity so an unusable rule cannot
appear harmless. Invalid rules are `fail` / `not-evaluated`, with diagnostic
`invalid-rule`. Valid siblings continue. Observation and evaluation failures
also produce `fail` / `not-evaluated`, with their own diagnostic codes.

If any instance or condition is not evaluated, the combined flavor is
`not-evaluated`; otherwise a known failed condition gives `gap`. Per-condition
and per-instance records retain the other outcomes. The report type includes
`not-applicable` for adapters; this increment has no applicability predicate.
There is no new exit-code policy in this API.

Reports retain the organization source, optional repository source, audited
commit, selected maturity, assignment outcomes, both same-id instances,
relaxation reasons and warnings. Conditions retain their expected input and a
SHA-256 digest of selected observed JSON. Raw file contents are not copied into
evidence. Source commit fields identify configuration, not the moment live
GitHub settings were observed.

## Fix plans

A failed equality check of file contents derives `set-file-content`, fixed by
Airlock through a PR. A failed equality check of a supported boolean repository
setting derives `set-repository-setting`, fixed by a person. Every other failure
states that no unambiguous coded fix is available. These are plans; this module
has no mutating endpoint or fix executor.

A rule can declare completion, replace the fix with a coded action or agent
guidance, or block the fix with a reason. Action inputs are schema-checked.
Both current derive actions supply every required input: path and contents for
`set-file-content`, setting and value for `set-repository-setting`. Completion
currently confirms identical inputs; there is no missing production input to
fill. The generic completion planner can fill missing inputs in a partial plan.
Its pure unit test demonstrates that extension behavior, not a reachable path
in the current derive catalog. A conflicting known input makes the
fix plan unavailable with a reason directing the author to an explicit
`mode: action` replacement. Completion never retargets a known path or setting.
Unknown action types make the rule invalid. The coded action catalog contains
only the two actions above. External model-backed evaluation is not registered.

## Scope and validation

A run accepts one account. Organization sources, repository sources, targets and
organization repository overrides must belong to that account. Scope errors
stop before observation. A caller must verify any GitHub credential through the
existing read-only verification path before constructing the probe adapter.
This module discovers no credential and launches no subprocess.

The focused regression suite is `cargo test -p airlock-core --test
configurable_rules`. It covers hierarchy, demand, invalid-rule isolation,
assignment uncertainty, batching, maturity, overrides and source identity.
