# Organization Rulesets

Read only when creating or altering a ruleset. See `README.md` in this folder.

## Principle

The trust boundary is the **tag**. Delivery publishes whatever the tag points
at, so anyone who can create or move a tag can publish arbitrary code. The
rulesets exist to make the tag trustworthy.

Delivery itself needs no ruleset. It consumes the trust these create.

**Immutability is universal; creation authority is release-tier.** Moving a
published tag is never legitimate anywhere. Creating a version tag is an
authority only repositories that publish need to grant.

## Branch rulesets

| Name                                               | Condition                              | Target            | Rules                                                                                                                                    | Bypass                                       |
| -------------------------------------------------- | -------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `require-pr-on-public-default`                     | `visibility:public`                    | `~DEFAULT_BRANCH` | `pull_request` with `allowed_merge_methods: [squash, rebase]`, one required approval, stale-review dismissal, thread resolution required | Release authority app only                   |
| `protect-default-history`                          | `visibility:public`                    | `~DEFAULT_BRANCH` | `non_fast_forward`; `required_linear_history`                                                                                            | **none**                                     |
| `restrict-update-default-for-public-release-repos` | `visibility:public props.release:true` | `~DEFAULT_BRANCH` | `update`                                                                                                                                 | Write role, org admin, release authority app |

`required_linear_history` is what mechanically enforces no merge commits.
`allowed_merge_methods` is what enforces squash-and-rebase-only.
`require_code_owner_review` is `false`, consistent with requiring no
`CODEOWNERS`.

## Bypass is per ruleset, not per rule

An actor exempted from a ruleset is exempted from **every rule in it**. That
single fact determines how rules must be grouped.

The release authority app has to bypass the pull-request requirement, because it
advances the default branch to a validated release commit without a pull
request. If `non_fast_forward` and `required_linear_history` sat in that same
ruleset, the app would silently gain the right to force-push and rewrite history
on every public default branch — far more than it needs.

Splitting them into `protect-default-history` with **no bypass at all** keeps
the release app to exactly one power: advance the ref. It cannot rewrite what is
already there.

**Group rules by who is allowed to escape them, not by what they protect.**
`immutable-tags` follows the same shape on the tag side: creation authority is
granted to an app, mutation authority to nobody.

## Tag rulesets

| Name                       | Condition                              | Target                                      | Rules                                    | Bypass                   |
| -------------------------- | -------------------------------------- | ------------------------------------------- | ---------------------------------------- | ------------------------ |
| `immutable-tags`           | `visibility:public`                    | `~ALL`                                      | `update`, `deletion`, `non_fast_forward` | **none**                 |
| `release-tag-authority`    | `visibility:public props.release:true` | `[0-9]*.[0-9]*.[0-9]*`                      | `creation`                               | `wyrd-release-authority` |
| `package-tag-authority`    | `visibility:public props.release:true` | per-ecosystem patterns                      | `creation`                               | `wyrd-package-tags`      |
| `reject-unclassified-tags` | `visibility:public props.release:true` | `~ALL` **excluding** the two patterns above | `creation`                               | **none**                 |

`immutable-tags` has no bypass at all, not even for a release app. Creating a
tag is an authority; moving one never is.

Package tag patterns currently in use: `@the-wyrding-way/*@*` and
`the_wyrding_way_*@*`. Extend per ecosystem as products adopt the tier.

## Rulesets are cumulative

A ref must satisfy **every** matching ruleset. A bypass on one does not exempt a
ref from another.

This is why `reject-unclassified-tags` cannot simply target `~ALL` — it would
match the legitimate release tags too and block them. The exclusion list is what
makes the composition work.

**Adding a new tag pattern therefore requires editing two rulesets**: the new
allow, and this one's exclusions. Miss the second and releases break; miss the
first and the pattern is silently unprotected.

## Order of operations

Create protections before removing any. Overlap is harmless; a gap is not.

1. `protect-default-history` and `immutable-tags` — no dependencies, no property
   needed. Create these **before** granting the release app any bypass
2. Correct `release` property values — see `custom-properties.md`
3. `release-tag-authority`, `package-tag-authority`, `reject-unclassified-tags`
4. Retire the superseded product-scoped rulesets

Creating `reject-unclassified-tags` before step 2 blocks tag creation on every
public repository, because the condition currently matches all of them.

## Superseded

The `tww-*` rulesets predate the generalized set and carry a product name on
what is organization infrastructure: `tww-global-release-tag`,
`tww-immutable-tags`, `tww-main-history-safety`, `tww-main-write-authority`,
`tww-package-release-tags`, `tww-reject-unclassified-tags`. Retire them once the
generalized rulesets cover the same ground, and verify bypass sets match exactly
before removing any.

## Reading rulesets

Effective rulesets are readable at repository scope with an ordinary read token.
Only the organization endpoint needs admin.

```bash
gh api "repos/<owner>/<repo>/rulesets?includes_parents=true"
gh api "repos/<owner>/<repo>/rules/branches/main"
```

**Bypass actor membership is not disclosed** by the effective repository API. It
can only be confirmed by the owner in the organization settings.
