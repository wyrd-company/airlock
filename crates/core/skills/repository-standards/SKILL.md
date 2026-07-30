---
name: repository-standards
description:
  Apply the public repository standard shipped by Airlock. Use when creating a
  public repository, auditing one for gaps, or preparing a private repository
  for publication. Covers Wyrd Company, Flapstack, and personal repositories;
  excludes forks, private work that will remain private, and archiving.
---

# Public Repository Standards

Use this skill for public, non-fork repositories governed by the standard.
Airlock is the durable upstream. A copy in an agent skill directory is an
installation from an Airlock release, not another authority.

## Authority and ownership

The compiled Airlock registry owns every rule id, statement, default severity,
section, applicability condition, and evaluation mode. The generated
`references/conformance.md` is the only human-readable conformance checklist.
It quotes the registry version and digest carried by the same binary.

Do not add normative checklists, rule summaries, required-file lists, or
paraphrased rules to this file or another hand-written reference. Link to the
relevant generated conformance section instead.

`references/check-guidance.md` owns practical inspection guidance. Its rule ids
are structural join keys validated in both directions against the registry;
they do not define or restate rules. The topics vocabulary, platform
references, templates, and the workflow guidance in this file are
hand-written. They explain how to work, not what constitutes conformance.

## Scope

Before acting, establish that this skill applies. If the repository is a fork,
follow upstream conventions. If it will remain private or is being archived,
use the procedure for that case instead.

## Choose a mode

- **Scaffold:** create or prepare a repository, consulting the generated
  checklist section by section. Ask the user when a rule calls for judgment or
  a repository-specific decision.
- **Audit:** evaluate the repository against every applicable entry in
  `references/conformance.md`. Prefer Airlock output for mechanical checks and
  use the joined guidance for manual inspection.
- **Publish:** run a complete audit before changing visibility, then resolve
  every gating finding and every unanswered judgment with the operator.

## Read the generated checklist first

Open `references/conformance.md` before inspecting or changing a repository.
Use its sections as the work order and its registry version and digest as the
identity of the standard being applied.

**Always cite a rule by id and statement together.** A rule id alone is not a
meaningful finding. Copy both from the generated reference or Airlock output;
never reconstruct the statement from memory.

For each applicable rule:

1. Read the generated statement, severity, evaluation mode, and joined
   guidance.
2. Gather the evidence named by the guidance without broadening or narrowing
   the statement.
3. Record the observed result. Unknown or inaccessible evidence is not a pass.
4. When reporting a gap, include the id, exact statement, observed evidence,
   and proposed next action.

## Work safely

- Treat Airlock audit output as evidence, not permission to mutate settings.
- Keep repository changes reviewable and scoped to the findings being closed.
- Ask before making judgment calls the registry deliberately leaves to a
  person.
- Re-run the relevant checks after changes; do not infer that a proposed fix
  worked.
- Prefer source artifacts over live interface edits when the repository
  already designates an artifact as authoritative.

## Reference routing

Read only what the current work needs:

- `references/conformance.md` — generated rule identity and the complete
  checklist.
- `references/check-guidance.md` — hand-written inspection hints joined into
  the generated checklist.
- `references/topics.md` — seeded topic vocabulary and selection guidance.
- `references/platform/` — organization-level platform context that is not
  repository conformance.
- `references/templates/` — candidate starting points. Adapt them to the
  repository and validate the result against the generated checklist; a
  template is not proof of conformance.

## Reporting

Report one repository-level work item unless the user requests another shape.
Group related gaps when they share one change, but preserve each rule's id and
exact statement in the evidence. Separate:

- mechanical failures Airlock established;
- manual judgments awaiting a person;
- evidence Airlock could not observe;
- findings intentionally authorized but not aligned; and
- applicable checks that are aligned.

Do not call a repository conformant while applicable evidence is missing or a
gating finding remains open.
