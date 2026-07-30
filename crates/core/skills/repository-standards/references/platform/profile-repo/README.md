# Profile Repository Contents

Reference versions of the files an account's `.github` repository carries. Copy
into `<account>/.github/`, then resolve the placeholders.

Read only when setting up or changing an account's defaults. See the parent
folder's `README.md`.

## Layout

```text
.github/
  profile/README.md          the public account page
  CODE_OF_CONDUCT.md         inherited by every repository
  SECURITY.md
  SUPPORT.md
  PULL_REQUEST_TEMPLATE.md
  ISSUE_TEMPLATE/
    bug_report.yml
    idea.yml
    config.yml
  default.json               shared Renovate preset
  workflows/                 reusable workflows, called explicitly per repo
```

A root `README.md` renders on the `.github` repository's own page and is
inherited by nothing. It is not the profile page — that is `profile/README.md`.

## Placeholders to resolve

| Placeholder                    | Appears in                        | Decision                                                                                                 |
| ------------------------------ | --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `<CONDUCT_CONTACT>`            | `CODE_OF_CONDUCT.md`              | An address that reaches a human who can act on a report. A role address ages better than a personal one. |
| `<ACCOUNT>`                    | `profile/README.md`, `SUPPORT.md` | The organization or account name                                                                         |
| `<TAGLINE>`, `<WHAT_WE_BUILD>` | `profile/README.md`               | Per account                                                                                              |

## Two consequences worth deciding before adoption

### Renovate cannot automerge

The default branch requires a pull request with one approval and **no bypass**.
Renovate merges as itself, so with no bypass it cannot complete a merge — every
dependency update needs a human approval, across every repository.

Three options, in order of preference:

1. **Accept it.** The dependency dashboard batches the work, and grouped updates
   keep the count low. Honest, and it preserves the no-bypass property.
2. **Grant Renovate a bypass** limited to pull requests it opened. This weakens
   the strongest guarantee in the ruleset design for convenience.
3. **Schedule updates** so they arrive predictably rather than continuously.
   Combines with option 1.

The preset here assumes option 1 and option 3: grouped, scheduled, dashboard
enabled, automerge off.

### The pull request template is authored here and read from GitHub

GitHub auto-applies exactly one default template. Additional ones require a
`?template=` URL parameter, which an outside contributor will never use, so the
default serves everyone.

`PULL_REQUEST_TEMPLATE.md` here is the source for what the `.github` repository
carries. Once it is deployed, **it is what everyone uses** — an agent preparing
a pull request queries GitHub for it rather than carrying a copy:

```bash
gh api graphql -f query='{ repository(owner:"OWNER", name:"REPO") {
  pullRequestTemplates { filename body } } }' \
  --jq '.data.repository.pullRequestTemplates[].body'
```

That query resolves a repository-local template first and falls back to this
one, matching GitHub's own precedence. The `task-execution` skill keeps a copy
only as a fallback for local `gitpr` reviews and offline work.

Editing this file therefore changes every repository at once, which is the point
— but it also means a mistake here lands everywhere. Deploy it like any other
change.

### Issues are bug reports, not work

The issue templates reflect that work is tracked on the kanban board, not in
GitHub issues. `bug_report.yml` collects what a bug report needs; `idea.yml` is
the entry point for an outside suggestion, and says plainly that acceptance is
decided elsewhere. Blank issues are disabled so neither becomes an accidental
work tracker.

If an account genuinely wants open-ended discussion, enable Discussions on the
repositories that want it and add a contact link in `config.yml`. Do not repeal
the blank-issue setting to get there.
