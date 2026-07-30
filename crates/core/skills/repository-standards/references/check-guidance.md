# Check Guidance

This hand-written reference owns practical guidance for applying each rule.
Rule ids, statements, severities, sections, and evaluation modes belong to the
compiled Airlock registry; `references/conformance.md` joins this guidance to
that registry projection.

| Id | Guidance |
| --- | --- |
| `REPO-ORG-01` | Judgment |
| `REPO-ORG-02` | Judgment |
| `REPO-NAME-01` | Repository name |
| `REPO-NAME-02` | Repository name |
| `REPO-NAME-03` | Repository name |
| `REPO-NAME-04` | Name vs topics |
| `REPO-META-01` | File contents |
| `REPO-META-02` | File contents |
| `REPO-META-03` | Read it |
| `REPO-META-04` | Read it |
| `REPO-META-05` | Compare |
| `REPO-META-06` | File contents |
| `REPO-META-07` | Compare against `topics.md` |
| `REPO-META-08` | Compare against `topics.md` |
| `REPO-META-09` | Compare against `topics.md` |
| `REPO-META-10` | File contents |
| `REPO-META-11` | File contents |
| `REPO-META-12` | File contents |
| `REPO-META-13` | `gh repo view` vs file — drift means reconciliation is not running |
| `REPO-LIC-01` | File presence |
| `REPO-LIC-02` | Judgment against the category table |
| `REPO-LIC-03` | `LICENSE`, package metadata |
| `REPO-LIC-04` | `package.json`, `Cargo.toml`, `pubspec.yaml` |
| `REPO-LIC-05` | Read the README |
| `REPO-LIC-06` | Read |
| `REPO-FILE-01` | File presence |
| `REPO-FILE-02` | File presence |
| `REPO-FILE-03` | File presence |
| `REPO-FILE-04` | File contents |
| `REPO-FILE-05` | File presence |
| `REPO-FILE-06` | File presence |
| `REPO-FILE-07` | File presence |
| `REPO-FILE-08` | File contents |
| `REPO-FILE-16` | File presence |
| `REPO-FILE-17` | File contents |
| `REPO-FILE-09` | File presence |
| `REPO-FILE-10` | File presence |
| `REPO-FILE-11` | File presence |
| `REPO-FILE-12` | `git ls-files -s CLAUDE.md` — mode `120000` |
| `REPO-FILE-13` | File presence |
| `REPO-FILE-14` | File presence |
| `REPO-FILE-15` | Compare against the org `.github` repository |
| `REPO-README-01` | Read |
| `REPO-README-02` | Read |
| `REPO-README-03` | Compare against published channels |
| `REPO-README-04` | Read |
| `REPO-README-05` | Read |
| `REPO-README-06` | File presence |
| `REPO-README-07` | Read |
| `REPO-README-08` | Read |
| `REPO-README-09` | Read |
| `REPO-GIT-01` | `gh repo view --json defaultBranchRef` |
| `REPO-GIT-02` | `gh api repos/{o}/{r}/rulesets?includes_parents=true` |
| `REPO-GIT-03` | `gh api repos/{o}/{r}/rules/branches/main` |
| `REPO-GIT-13` | Workflow source |
| `REPO-GIT-14` | Workflow source |
| `REPO-GIT-04` | `gh repo view --json mergeCommitAllowed` |
| `REPO-GIT-05` | `gh repo view --json squashMergeAllowed` |
| `REPO-GIT-06` | `gh repo view --json deleteBranchOnMerge` |
| `REPO-GIT-07` | `gh repo view` |
| `REPO-GIT-08` | `git tag` |
| `REPO-GIT-09` | `git tag` |
| `REPO-GIT-10` | `git log --merges` |
| `REPO-TASK-01` | `task --list-all` |
| `REPO-TASK-02` | `task --list-all` plus the recorded decision |
| `REPO-TASK-03` | Compare taskfile against workflows |
| `REPO-TASK-04` | File presence per `.intentional/config.yml` |
| `REPO-TASK-05` | Root `taskfile.yml` |
| `REPO-TASK-06` | Compare against `.intentional/config.yml` |
| `REPO-CI-01` | Workflow contents |
| `REPO-CI-02` | Workflow contents |
| `REPO-CI-03` | Workflow contents |
| `REPO-CI-04` | Workflow contents |
| `REPO-CI-05` | Workflow contents |
| `REPO-CI-06` | Workflow contents |
| `REPO-CI-07` | Workflow contents |
| `REPO-CI-08` | Workflow contents and ruleset |
| `REPO-CI-09` | Workflow contents |
| `REPO-CI-10` | Workflow contents |
| `REPO-CD-01` | File presence |
| `REPO-CD-02` | Workflow contents |
| `REPO-CD-03` | Workflow contents |
| `REPO-CD-04` | Workflow contents |
| `REPO-CD-05` | Dispatch inputs and their use |
| `REPO-CD-06` | Workflow contents |
| `REPO-CD-07` | Workflow contents |
| `REPO-HOOK-01` | `.config/lefthook.yml` |
| `REPO-HOOK-02` | `.config/lefthook.yml` |
| `REPO-HOOK-03` | `.config/lefthook.yml` |
| `REPO-HOOK-04` | `.config/lefthook.yml` |
| `REPO-AGENT-01` | Read |
| `REPO-AGENT-02` | Read |
| `REPO-AGENT-03` | Compare |
| `REPO-AGENT-04` | Read |
| `REPO-AGENT-05` | File contents |
| `REPO-DOCS-01` | Directory listing |
| `REPO-DOCS-02` | Directory listing |
| `REPO-DOCS-03` | File inspection |
| `REPO-DOCS-04` | File presence plus the recorded decision |
| `REPO-DOCS-05` | schemas may resolve outside the bounded repository snapshot |
| `REPO-REL-01` | File presence |
| `REPO-REL-02` | Compare against `.intentional/config.yml` |
| `REPO-REL-03` | File presence |
| `REPO-REL-04` | Workflow contents |
| `REPO-REL-05` | Workflow contents |
| `REPO-REL-06` | Workflow contents |
| `REPO-REL-07` | Workflow contents |
| `REPO-PROP-03` | File contents |
| `REPO-PROP-04` | Workflow contents |
