# Templates

Starting files for the mechanical requirements — the ones where a template
produces a correct file rather than filler.

| Template                 | Destination                                |
| ------------------------ | ------------------------------------------ |
| `gitattributes`          | `.gitattributes`                           |
| `editorconfig`           | `.editorconfig`                            |
| `renovate.json`          | `.github/renovate.json`                    |
| `lefthook.yml`           | `.config/lefthook.yml`                     |
| `taskfile.yml`           | `taskfile.yml`                             |
| `ci.yml`                 | `.github/workflows/ci.yml`                 |
| `repo-settings.yml`      | `.github/repo-settings.yml`                |
| `reconcile-settings.yml` | `.github/workflows/reconcile-settings.yml` |

There is deliberately **no template for `README.md`, `AGENTS.md`, or
`CONTRIBUTING.md`.** Those require judgment, and a template produces filler that
survives review because it looks finished.

## Pinning actions

Every `uses:` in `ci.yml` carries a **null SHA** — forty zeros — and a trailing
comment naming the tag to resolve:

```yaml
- uses: actions/checkout@0000000000000000000000000000000000000000 # v4
```

A null SHA is not a valid ref, so an unresolved template fails loudly instead of
silently running something unintended. Resolve every one when setting up or
fixing a workflow:

```bash
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha
```

An action pinned to a tag is an action whose code can change under you. Renovate
updates pinned SHAs and keeps the comment current.
