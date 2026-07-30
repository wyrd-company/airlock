# Organization Platform Configuration

> **Do not read this folder while scaffolding or auditing a repository.**
>
> The repository standard relies on this configuration but neither validates nor
> manages it. An agent creating a new repository, or auditing an existing one,
> has no reason to open these files and should not — the facts it needs are
> already stated in `SKILL.md` under _What this standard relies on_.
>
> Read this folder only when **changing** organization platform configuration:
> creating or altering a GitHub App, a ruleset, a custom property, an
> organization secret, or an environment.

## Why it is separate

Repository standards and platform configuration answer different questions and
change at different rates.

|             | Question                           | Who changes it                | How often  |
| ----------- | ---------------------------------- | ----------------------------- | ---------- |
| `SKILL.md`  | What must this repository contain? | Anyone authoring a repository | Constantly |
| This folder | What exists in the organization?   | The owner, deliberately       | Rarely     |

Mixing them made the standard hard to follow and implied that an auditing agent
should verify platform state it has neither the permission nor the mandate to
touch.

## Contents

| File                          | Covers                                                        |
| ----------------------------- | ------------------------------------------------------------- |
| `github-apps.md`              | Capabilities, permissions, installation, credentials          |
| `rulesets.md`                 | Organization rulesets, conditions, rules, bypass actors       |
| `custom-properties.md`        | Classification vocabulary and how values are assigned         |
| `secrets-and-environments.md` | Organization and environment secrets, variables, environments |

## Scope

Covers `wyrd-company`, `flapstack`, and `boblangley`.

Every account owns a `.github` repository, so default community health files are
inherited uniformly. `mmenm` holds lab work, which is private and outside the
repository standard, but its defaults exist for consistency.

The same repository also renders the public profile page, from
`profile/README.md`, for organizations and personal accounts alike. A personal
account may instead use a repository named after the account, but that is a
second mechanism for the same result and there is no reason to run both.
