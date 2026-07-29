# Working in this repository

Airlock is a read-only auditor. Two crates: `airlock-core` holds the check
registry, policy resolution, findings model, and GitHub client; `airlock-cli` is
a thin front end that parses arguments and renders. Logic belongs in core —
if a command handler grows a decision, that decision is in the wrong crate.

Run `task check` before pushing; it is what CI runs. Everything else is in
`taskfile.yml`.

## Constraints that are not negotiable

**The audit never writes.** `airlock audit` and every headless surface hold no
mutating endpoint and refuse any credential that could write. The interactive
align session alone may apply settings-level remediations — under an
operator's device-flow grant held only in memory — and it never writes files.

**The binary never shells out.** No `git`, no `gh`, no subprocess at all from
`airlock` or anything it depends on. Airlock speaks the GitHub REST API
directly. This is a rule about the binary, not about the repository:
`.github/workflows/reconcile-settings.yml` uses `gh` deliberately, because a
workflow holding a scoped token is exactly where a write belongs.

**No ambient credentials.** `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential
store, and git credential helpers are off limits as sources and must not be
mentioned as fallbacks in error messages. Suggesting them defeats the point of
refusing write access.

**A token whose permissions cannot be enumerated is refused.** Unverifiable is
not a warning path. Adding a token prefix means adding the introspection that
proves it read-only, or refusing it.

**Check identity is compiled in.** Rule ids, statements, and default severities
live in the registry in `crates/core/src/registry.rs`, not in policy files. A
policy selects, parameterises, and re-grades; it cannot define a check or
express a predicate. If a policy needs to say something the checks cannot, the
answer is a new check.

**A rule that is not implemented is registered, not omitted.** Silent absence
is the failure mode that makes an audit tool untrustworthy.

## What not to touch

`.github/repo-settings.yml` is the source of truth for repository metadata and
is applied by `.github/workflows/reconcile-settings.yml`. Editing settings in
the GitHub web interface is not a change; the next reconcile reverts it.

Version numbers are computed at release time from `.intentional/config.yml`. Do
not hand-edit the version in `Cargo.toml` or write a release entry in
`CHANGELOG.md`.

Action pins are full commit SHAs with a version comment. Renovate moves them.
Do not replace a pin with a tag.

## Where things live

The rules airlock checks come from the `repository-standards` conformance
document, which is the source of truth for their wording and severity — the
registry mirrors it, and drift is resolved in favour of the document.

`docs/examples/` holds candidate copies of files that belong elsewhere — the
organisation policy and its topic vocabulary live in `wyrd-company/.github`
once an operator moves them. An integration test compiles the candidate policy
against the compiled registry, so it cannot rot in place.

Wider design context lives in memory and in the kanban task, not here.
