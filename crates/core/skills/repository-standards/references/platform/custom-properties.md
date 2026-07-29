# Custom Properties

Read only when creating or altering a property, or assigning values. See
`README.md` in this folder.

## Purpose

Custom properties classify repositories so organization rulesets can target them
directly. They are how a ruleset knows a repository publishes versioned
artifacts and therefore needs tag authority.

They are also the machine-readable answer to questions the repository standard
would otherwise resolve by judgment — _is this a tool?_, _does it publish?_, _is
this a site?_ Prefer a property over an inference wherever one exists.

## Properties must stay organization-managed

**A property is never reconciled from the repository it classifies.** It must
not appear in `.github/repo-settings.yml`, and no workflow may set one.

This is a security boundary, not a preference. Rulesets are targeted by these
values, so a repository able to declare its own could edit one line and opt
itself out of the protections that govern it. The classification has to sit
outside the blast radius of the thing it classifies.

That is the opposite of the rule for description, topics, and merge settings,
which are cosmetic and safely self-declared.

## Vocabulary

| Property    | Values           | Meaning                                                         |
| ----------- | ---------------- | --------------------------------------------------------------- |
| `release`   | `true` / `false` | Something downstream pins a version of this repository's output |
| `product`   | product name     | Which product this repository belongs to                        |
| `component` | `true` / `false` | The repository is a component of a larger product               |
| `website`   | `true` / `false` | The repository deploys a site                                   |

## Assigning `release`

> `release` is `true` when something downstream **pins a version** of this
> repository's output.

A deployed site has consumers but nobody pins it. A published CLI, library, or
package does.

By that test a documentation site is `false` even though it is deployed
continuously, and a command-line tool distributed through a package manager is
`true`.

## Reading values

```bash
gh api "repos/<owner>/<repo>/properties/values"
```

The organization schema endpoint (`orgs/<org>/properties/schema`) requires
elevated permission and is not readable with an ordinary token.

## A property with a default is not a classification

A property created with a default value applies that value to every existing
repository at once. Until values are set deliberately, a ruleset condition on
that property selects everything and the targeting is decorative.

Verify values before relying on a property to scope a ruleset — particularly
before creating a ruleset that _denies_ an operation, since an over-broad match
will block repositories that were never meant to be in scope.
