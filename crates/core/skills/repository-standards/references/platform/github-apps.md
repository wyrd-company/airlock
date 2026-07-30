# GitHub Apps

Read only when creating or altering an app. See `README.md` in this folder.

## Principle

Apps are split by **capability**, never by product. One app performs one kind of
write, so holding its key grants nothing another app holds.

An app's _permissions_ define its capability; its _installation_ defines its
reach. Product scoping is therefore unnecessary — install an app only where it
is needed.

Apps are account-owned. Each organization that needs a capability owns its own
instance. Do not make an app public to share it across organizations; that
publishes its existence and permission set and invites installation requests.

## Installation is not a boundary

GitHub does not let custom properties drive installation. It is a hand-selected
list that drifts from the classification the moment a repository is created, and
nothing reports the drift.

Installation breadth is the **blast radius of a leaked private key** — whoever
holds it can mint a token for any repository the app is installed on, whatever
the workflow requested.

The boundary that holds is the **ruleset bypass**, which _is_
property-conditioned. An app installed everywhere still cannot create a
protected tag where no ruleset grants it bypass.

Three layers, in decreasing reliability:

| Layer                           | Enforced by                  | Reliability                  |
| ------------------------------- | ---------------------------- | ---------------------------- |
| Ruleset bypass                  | GitHub, property-conditioned | Strong — the actual boundary |
| Token `repositories:` narrowing | The workflow requesting it   | Only as good as the workflow |
| Installation list               | A human maintaining it       | Drifts silently              |

Assert the third layer, since GitHub will not: a scheduled check comparing
`GET /installation/repositories` against the repositories carrying the matching
property is the only thing that makes installation drift visible.

## Registry

| App                      | Capability                                                                             | Permissions                    |
| ------------------------ | -------------------------------------------------------------------------------------- | ------------------------------ |
| `wyrd-release-authority` | Advance the default branch to a validated release commit; create its global SemVer tag | Contents: write                |
| `wyrd-package-tags`      | Create validated per-package tags                                                      | Contents: write                |
| `wyrd-docs-publisher`    | Write `content/<tool>/` in the docs tap                                                | Contents: write                |
| `wyrd-dependency-reader` | Read sibling private repositories and packages during CI                               | Contents: read, Packages: read |
| `wyrd-repo-settings`     | Apply `.github/repo-settings.yml`                                                      | Administration: write          |

Metadata: read is mandatory and granted automatically on all apps.

`wyrd-release-authority` and `wyrd-package-tags` stay separate because the
rulesets grant them different tag-creation bypasses. Merging them collapses that
boundary.

`wyrd-repo-settings` has the widest installation, so it holds **no** Contents
permission — it cannot alter code, only settings.

## Credentials

An app contributes two entries, named from its capability:

- `<CAPABILITY>_APP_ID` — a **variable**. An app id is not secret; it appears in
  release documentation already, and storing it as a variable means it can be
  read back to verify.
- `<CAPABILITY>_APP_PRIVATE_KEY` — a **secret**.

Store private keys as **environment** secrets wherever an approval boundary
exists, never at organization scope.

Never name a credential after the task that introduced it. A task number is
meaningless once the task closes, and the credential outlives it.
