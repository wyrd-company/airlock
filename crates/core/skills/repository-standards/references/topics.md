# Topic Vocabulary

Seed vocabulary for GitHub topics, organized by facet. Three to eight topics per
repository.

**This list is seeded, not closed.** Prefer an existing term. When a repository
genuinely needs a new one, add it here in the same change.

GitHub constraints: lowercase alphanumeric and hyphens, at most 50 characters
per topic, at most 20 topics per repository.

## Facets

| Facet          | Required        | Answers                           |
| -------------- | --------------- | --------------------------------- |
| Artifact type  | Yes             | What do I get?                    |
| Ecosystem      | Yes             | How do I install or run it?       |
| Domain         | No              | What problem space is this?       |
| Product family | When applicable | What else is part of this system? |

## Artifact type

`cli` · `library` · `mcp-server` · `container` · `devcontainer-feature` ·
`github-action` · `schema` · `spec` · `website` · `browser-extension` · `tui` ·
`bot`

## Ecosystem

`rust` · `typescript` · `javascript` · `go` · `python` · `dotnet` · `dart` ·
`flutter` · `shell` · `docker` · `npm` · `cargo` · `homebrew` · `apt` · `rpm` ·
`aur` · `bun` · `astro`

## Domain

`ai-agents` · `mcp` · `release-automation` · `versioning` · `changelog` ·
`devcontainers` · `homelab` · `git` · `github` · `pull-request` · `web-search` ·
`web-scraping` · `embeddings` · `networking` · `ssh` · `svg` · `pty` · `devops`
· `package-registry`

## Product family

Add a family topic when a repository is one part of a system spanning several
repositories. This is the highest-value facet, because it is the only thing that
makes a family visible across orgs — GitHub's own grouping stops at the org
boundary.

`agent-host-protocol` · `refinery` · `the-wyrding-way`

## Normalization

Pick one term per concept. Synonyms fragment search and defeat the point.

| Use         | Not                                                      |
| ----------- | -------------------------------------------------------- |
| `ai-agents` | `ai-agent`, `agentic-ai`, `agent-tools`, `agent-tooling` |
| `cli`       | `command-line-tool`, `npm-cli`                           |
| `git`       | `git-tag`, `git-tags`                                    |
| `apt`       | `deb`, `apt-repository`                                  |
| `rpm`       | `rpm-repository`                                         |
| `aur`       | `aur-packages`                                           |
| `website`   | `product-website`                                        |

Plural for concept collections (`ai-agents`), singular for a named technology
(`git`, `rust`).

## Before coining a term

Survey what is already in use, so you adopt or normalize rather than inventing a
third synonym:

```bash
for o in wyrd-company boblangley mmenm flapstack; do
  gh repo list "$o" --visibility public --limit 200 \
    --json repositoryTopics --jq '.[].repositoryTopics[]?.name'
done | sort | uniq -c | sort -rn
```

If the survey shows a near-synonym already in the wild, either adopt it or
normalize both to one term — do not add a third.
