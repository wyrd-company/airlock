//! The check registry.
//!
//! Check identifiers, statements, and default severities are compiled into the
//! binary rather than loaded from the conformance document, so a released
//! binary always reports what it actually evaluated. A policy may select,
//! parameterise, and re-grade a registered check; it cannot define one.
//!
//! Checks are grouped into sections a policy selects through capabilities, and
//! each carries an evaluation mode: mechanical checks run against the GitHub
//! API, judgment checks are registered as manual and surfaced for a human, and
//! checks not yet written are registered as unimplemented so they are visibly
//! absent rather than silently absent.
//!
//! The statements here are verbatim copies of the conformance checklist. A
//! test in `tests/conformance.rs` parses a committed copy of that document and
//! fails on any drift, in either direction.

use std::fmt;

use sha2::{Digest, Sha256};

/// The semantic version of the compiled registry.
///
/// It moves when the set of rules, their statements, their default severities,
/// evaluation modes, or applicability conditions change. Policies constrain it with
/// `requires-registry`.
pub const REGISTRY_VERSION: &str = "0.4.0";

/// A built-in condition that determines whether a check applies.
///
/// Applicability is part of check identity: policies may select and re-grade
/// checks, but they cannot broaden a check beyond the repositories its
/// compiled statement governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    /// The check applies to every repository that selects it.
    Always,
    /// The check applies only when at least one release unit is declared.
    ReleaseUnitsDeclared,
}

impl Applicability {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::ReleaseUnitsDeclared => "release-units-declared",
        }
    }
}

/// How severely a failure counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The repository should not be public in this state.
    Blocking,
    /// A genuine gap; raise it.
    Required,
    /// Report it; it may be a deliberate choice or a not-yet-live practice.
    Observation,
}

impl Severity {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Severity::Blocking => "blocking",
            Severity::Required => "required",
            Severity::Observation => "observation",
        }
    }

    /// Parse a severity from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "blocking" => Some(Severity::Blocking),
            "required" => Some(Severity::Required),
            "observation" => Some(Severity::Observation),
            _ => None,
        }
    }

    /// Every severity, in order of decreasing weight.
    pub const ALL: &'static [Severity] = &[
        Severity::Blocking,
        Severity::Required,
        Severity::Observation,
    ];
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// The section of the conformance checklist a rule belongs to.
///
/// Sections are what a policy's `capabilities` select. Membership can grow as
/// the registry grows; a policy that wants immunity from that names rule ids
/// explicitly instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// Organisation placement, naming, and declared metadata.
    Identity,
    /// Licence choice and declaration.
    Licensing,
    /// Required and forbidden files.
    Files,
    /// README structure.
    Readme,
    /// Git and platform configuration.
    Git,
    /// Taskfiles, CI, CD, and hooks.
    Automation,
    /// Agent affordances.
    Agent,
    /// Documentation layout.
    Docs,
    /// Release units, changelogs, and release workflows.
    Release,
    /// Custom property classification.
    Classification,
}

impl Section {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Section::Identity => "identity",
            Section::Licensing => "licensing",
            Section::Files => "files",
            Section::Readme => "readme",
            Section::Git => "git",
            Section::Automation => "automation",
            Section::Agent => "agent",
            Section::Docs => "docs",
            Section::Release => "release",
            Section::Classification => "classification",
        }
    }

    /// Parse a section from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Section::ALL
            .iter()
            .copied()
            .find(|section| section.code() == value)
    }

    /// Every section, in registry order.
    pub const ALL: &'static [Section] = &[
        Section::Identity,
        Section::Licensing,
        Section::Files,
        Section::Readme,
        Section::Git,
        Section::Automation,
        Section::Agent,
        Section::Docs,
        Section::Release,
        Section::Classification,
    ];
}

impl fmt::Display for Section {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// How a rule is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Evaluation {
    /// Airlock evaluates it against the GitHub API.
    ///
    /// A mechanical rule with a judgment clause still fails mechanically on
    /// the part it can decide, and defers the rest to a human rather than
    /// claiming a pass it cannot prove.
    Mechanical,
    /// The rule is a judgment call. Airlock reports it for a human and it
    /// never gates.
    Manual,
    /// The rule is registered but not yet built. Enabling it makes an audit
    /// incomplete rather than silently narrower.
    Unimplemented,
}

impl Evaluation {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Evaluation::Mechanical => "mechanical",
            Evaluation::Manual => "manual",
            Evaluation::Unimplemented => "unimplemented",
        }
    }
}

impl fmt::Display for Evaluation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// What a rule observes: the repository's file tree, or platform state that
/// only the GitHub API can report.
///
/// The domain decides which observation source can answer for the rule. A
/// file-tree rule can be evaluated from the API tree or from a local working
/// tree; a platform rule has no local equivalent and is never inferred from
/// one — without the API it is reported as not observed, never as passing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The rule reads committed (or, locally, working-tree) file content.
    FileTree,
    /// The rule reads live platform state: settings, rulesets, tags, history,
    /// secrets, or anything else the API owns.
    Platform,
}

impl Observation {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Observation::FileTree => "file-tree",
            Observation::Platform => "platform",
        }
    }
}

/// One registered check definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckDefinition {
    /// The check definition id, for example `REPO-LIC-01`.
    pub id: &'static str,
    /// The check definition statement, verbatim from the conformance checklist.
    pub statement: &'static str,
    /// The default severity, verbatim from the conformance checklist.
    pub severity: Severity,
    /// The section the rule belongs to.
    pub section: Section,
    /// How the rule is evaluated.
    pub evaluation: Evaluation,
    /// The parameter names a policy may set on this rule.
    pub params: &'static [&'static str],
}

/// Every registered check definition, in conformance document order.
pub const CHECKS: &[CheckDefinition] = &[
    CheckDefinition {
        id: "REPO-ORG-01",
        statement: "The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good",
        severity: Severity::Observation,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-ORG-02",
        statement: "A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company`",
        severity: Severity::Observation,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-NAME-01",
        statement: "The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-NAME-02",
        statement: "A dotted name is used only where the repository is a deployable site and the name is its hostname",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-NAME-03",
        statement: "A repository in a product family carries the family prefix",
        severity: Severity::Observation,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-NAME-04",
        statement: "The family prefix and the family topic agree",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-01",
        statement: "`.github/repo-settings.yml` declares a description",
        severity: Severity::Blocking,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-02",
        statement: "The description is one sentence, at most 160 characters, and survives truncation at ~80",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-03",
        statement: "The description expands any acronym on first use",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-04",
        statement: "The description contains no self-deprecation",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-05",
        statement: "The description agrees with the README's opening line",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-06",
        statement: "Between three and eight topics are declared",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &["min-topics", "max-topics"],
    },
    CheckDefinition {
        id: "REPO-META-07",
        statement: "Topics include at least one artifact-type and one ecosystem term",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-08",
        statement: "A repository in a product family carries the family topic",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-09",
        statement: "Any topic not in `topics.md` has been added to it",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-10",
        statement: "No org-name topic is declared",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &["org-names"],
    },
    CheckDefinition {
        id: "REPO-META-11",
        statement: "The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted",
        severity: Severity::Required,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-12",
        statement: "`.github/repo-settings.yml` declares no `visibility` field",
        severity: Severity::Blocking,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-META-13",
        statement: "Live GitHub metadata matches the declared file",
        severity: Severity::Observation,
        section: Section::Identity,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-01",
        statement: "A `LICENSE` file exists",
        severity: Severity::Blocking,
        section: Section::Licensing,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-02",
        statement: "The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license",
        severity: Severity::Required,
        section: Section::Licensing,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-03",
        statement: "The repository is not dual-licensed `MIT OR Apache-2.0`",
        severity: Severity::Blocking,
        section: Section::Licensing,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-04",
        statement: "A repository publishing to a registry declares the license in package metadata",
        severity: Severity::Required,
        section: Section::Licensing,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-05",
        statement: "A plumbing repository's README states that the license covers packaging, not payload",
        severity: Severity::Required,
        section: Section::Licensing,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-LIC-06",
        statement: "A non-default license choice has a stated reason in the README or a decision record",
        severity: Severity::Observation,
        section: Section::Licensing,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-01",
        statement: "`README.md` exists",
        severity: Severity::Blocking,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-02",
        statement: "`CONTRIBUTING.md` exists in the repository, not only at org level",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-03",
        statement: "`.gitignore` exists and is ecosystem-appropriate",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-04",
        statement: "`.gitattributes` exists and normalizes line endings",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-05",
        statement: "`.editorconfig` exists",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-06",
        statement: "`taskfile.yml` exists, lowercase",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-07",
        statement: "`.github/workflows/` contains at least a CI workflow triggered on pull request",
        severity: Severity::Blocking,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-08",
        statement: "`.github/renovate.json` exists and extends the org preset",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &["renovate-preset"],
    },
    CheckDefinition {
        id: "REPO-FILE-16",
        statement: "`.github/repo-settings.yml` exists",
        severity: Severity::Blocking,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-17",
        statement: "`.github/workflows/audit.yml` exists and triggers on a schedule and on demand",
        severity: Severity::Blocking,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-09",
        statement: "`.config/lefthook.yml` exists",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-10",
        statement: "`.devcontainer/` exists",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-11",
        statement: "`AGENTS.md` exists",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-12",
        statement: "`CLAUDE.md` exists and is a symlink to `AGENTS.md`",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-13",
        statement: "No agent harness configuration is committed — no `.claude/`, `.cursor/`, or equivalent",
        severity: Severity::Required,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &["forbidden-paths"],
    },
    CheckDefinition {
        id: "REPO-FILE-14",
        statement: "No `CODEOWNERS` file is present",
        severity: Severity::Observation,
        section: Section::Files,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-FILE-15",
        statement: "Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs",
        severity: Severity::Observation,
        section: Section::Files,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-01",
        statement: "Opens with a title and a one-line statement of what it is",
        severity: Severity::Required,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-02",
        statement: "Badges are present",
        severity: Severity::Required,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-03",
        statement: "An installation section covers every supported channel",
        severity: Severity::Blocking,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-04",
        statement: "A quickstart or usage section contains at least one real, runnable example",
        severity: Severity::Blocking,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-05",
        statement: "A repository with a user interface has an animated demo",
        severity: Severity::Observation,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-06",
        statement: "Where a demo exists, its `.tape` source is committed",
        severity: Severity::Required,
        section: Section::Readme,
        // Mechanical scope: the committed-demo proxy is a regular file whose
        // basename is `demo.gif`, matching the repository VHS convention.
        // REPO-README-05 retains the judgment of what other media is a demo.
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-07",
        statement: "Prerequisites appear only where non-obvious",
        severity: Severity::Observation,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-08",
        statement: "No license section",
        severity: Severity::Required,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-README-09",
        statement: "No contributing section",
        severity: Severity::Required,
        section: Section::Readme,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-01",
        statement: "The default branch is `main`",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-02",
        statement: "The repository is covered by organization-sourced rulesets on its default branch",
        severity: Severity::Blocking,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-03",
        statement: "Those rulesets require pull requests, allow only squash and rebase, and require linear history",
        severity: Severity::Blocking,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-13",
        statement: "A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY`",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-14",
        statement: "No secret or variable is named after the task that introduced it",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-04",
        statement: "Merge commits are disabled",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-05",
        statement: "Squash merge is enabled",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-06",
        statement: "Auto-delete head branch on merge is enabled",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-07",
        statement: "Wikis, Projects, and Discussions are off unless deliberately used",
        severity: Severity::Observation,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-08",
        statement: "Tags carry no `v` prefix",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-09",
        statement: "Multi-release-unit tags use `@scope/name@version`",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-GIT-10",
        statement: "History contains no merge commits",
        severity: Severity::Required,
        section: Section::Git,
        evaluation: Evaluation::Mechanical,
        params: &["max-commits"],
    },
    CheckDefinition {
        id: "REPO-TASK-01",
        statement: "`test`, `lint`, `format`, and `check` tasks exist",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-TASK-02",
        statement: "Applicability of `build` and `dev` was an explicit decision, and they exist where applicable",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-TASK-03",
        statement: "`task check` runs everything CI runs",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-TASK-04",
        statement: "In a monorepo, each release unit has a `taskfile.yml` at its path",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-TASK-05",
        statement: "Every include sets `dir:`",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-TASK-06",
        statement: "Include namespaces match release unit ids",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-01",
        statement: "CI is triggered on `pull_request`",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-02",
        statement: "Workflow-level `permissions:` is set to `{}`",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-03",
        statement: "Every job declares only the permissions it needs",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-04",
        statement: "Every action is pinned to a full commit SHA with a version comment",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-05",
        statement: "No workflow uses `pull_request_target`",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-06",
        statement: "A `concurrency` group with `cancel-in-progress` covers pull requests",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-07",
        statement: "Every job invokes a task rather than a raw command",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-08",
        statement: "A required check validates pull request title format",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-09",
        statement: "The scheduled audit workflow uses a verified read-only `AIRLOCK_TOKEN`",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CI-10",
        statement: "No workflow mutates repository settings",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-01",
        statement: "A repository that delivers anything has `.github/workflows/cd.yml`",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-02",
        statement: "A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*`",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &["tag-pattern"],
    },
    CheckDefinition {
        id: "REPO-CD-03",
        statement: "A repository deploying a site or service triggers CD on push to the default branch",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-04",
        statement: "CD sets `concurrency` with `cancel-in-progress: false`",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-05",
        statement: "A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release",
        severity: Severity::Blocking,
        section: Section::Automation,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-06",
        statement: "CD asserts every required publication credential is present before doing any work",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-CD-07",
        statement: "Release creation and delivery are separate workflows",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-HOOK-01",
        statement: "`pre-commit` runs `format` and `lint` on staged files only",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-HOOK-02",
        statement: "`commit-msg` validates conventional commit format",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-HOOK-03",
        statement: "`pre-push` runs nothing or lint only",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-HOOK-04",
        statement: "Hooks invoke tasks rather than raw commands",
        severity: Severity::Required,
        section: Section::Automation,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-AGENT-01",
        statement: "`AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live",
        severity: Severity::Required,
        section: Section::Agent,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-AGENT-02",
        statement: "`AGENTS.md` contains nothing discoverable by reading the repository",
        severity: Severity::Required,
        section: Section::Agent,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-AGENT-03",
        statement: "`AGENTS.md` does not restate the README or `CONTRIBUTING.md`",
        severity: Severity::Required,
        section: Section::Agent,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-AGENT-04",
        statement: "`CONTRIBUTING.md` contains no command sequences beyond `task check`",
        severity: Severity::Required,
        section: Section::Agent,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-AGENT-05",
        statement: "Generated directories are marked `linguist-generated=true` in `.gitattributes`",
        severity: Severity::Required,
        section: Section::Agent,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-DOCS-01",
        statement: "User-facing pages sit at the top level of `docs/`",
        severity: Severity::Observation,
        section: Section::Docs,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-DOCS-02",
        statement: "Engineering artifacts sit in `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`",
        severity: Severity::Observation,
        section: Section::Docs,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-DOCS-03",
        statement: "Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field",
        severity: Severity::Observation,
        section: Section::Docs,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-DOCS-04",
        statement: "A tool publishing docs to `wyrd.foo` has `docs/docs.yml`",
        severity: Severity::Required,
        section: Section::Docs,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-DOCS-05",
        statement: "Schema-bound YAML artifacts follow their schema where one exists",
        severity: Severity::Observation,
        section: Section::Docs,
        // Manual: schema references may resolve outside the bounded repository
        // snapshot. The registry-owned evaluation reason records why partial
        // validation was rejected and is surfaced in listings and findings.
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-01",
        statement: "`.intentional/config.yml` exists and declares release units",
        severity: Severity::Required,
        section: Section::Release,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-02",
        statement: "A `CHANGELOG.md` exists at each release unit's declared path",
        severity: Severity::Required,
        section: Section::Release,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-03",
        statement: "A multi-unit repository has no root aggregate changelog",
        severity: Severity::Required,
        section: Section::Release,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-04",
        statement: "Release is `workflow_dispatch` on a pinned source SHA",
        severity: Severity::Blocking,
        section: Section::Release,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-05",
        statement: "The release workflow asserts the pinned SHA equals current `main`",
        severity: Severity::Blocking,
        section: Section::Release,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-06",
        statement: "The release workflow asserts a successful push-event CI run for exactly that SHA",
        severity: Severity::Blocking,
        section: Section::Release,
        evaluation: Evaluation::Manual,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-REL-07",
        statement: "No workflow publishes automatically on merge",
        severity: Severity::Blocking,
        section: Section::Release,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-PROP-03",
        statement: "`.github/repo-settings.yml` declares no custom property values",
        severity: Severity::Blocking,
        section: Section::Classification,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
    CheckDefinition {
        id: "REPO-PROP-04",
        statement: "No workflow writes organization custom properties",
        severity: Severity::Blocking,
        section: Section::Classification,
        evaluation: Evaluation::Mechanical,
        params: &[],
    },
];

/// Look a check definition up by id.
#[must_use]
pub fn find(id: &str) -> Option<&'static CheckDefinition> {
    CHECKS.iter().find(|check| check.id == id)
}

/// Every check definition in a section, in registry order.
#[must_use]
pub fn in_section(section: Section) -> Vec<&'static CheckDefinition> {
    CHECKS
        .iter()
        .filter(|check| check.section == section)
        .collect()
}

impl CheckDefinition {
    /// Why a non-mechanical evaluation mode is the honest boundary.
    ///
    /// This is registry data rather than only implementation commentary so
    /// operators see the classification boundary in listings and findings.
    #[must_use]
    pub fn evaluation_reason(&self) -> Option<&'static str> {
        match self.id {
            "REPO-DOCS-05" => Some(
                "Schema discovery can leave the bounded repository snapshot. Partial validation \
                 of only in-snapshot schemas was rejected because a manual finding communicates \
                 the whole-repository judgment consistently; mixing passes with inconclusive \
                 results based on schema location would make identical artifact classes gate \
                 differently.",
            ),
            _ => None,
        }
    }

    /// The repository state under which this check's statement applies.
    #[must_use]
    pub fn applicability(&self) -> Applicability {
        match self.id {
            "REPO-GIT-09" | "REPO-TASK-04" | "REPO-LIC-04" => Applicability::ReleaseUnitsDeclared,
            _ => Applicability::Always,
        }
    }

    /// What the rule observes.
    ///
    /// Declared here, per rule, and read everywhere — the audit gates
    /// platform rules on API availability from this, and every finding's
    /// `source` is derived from it. Like remediation classification, the
    /// domain is not part of the registry digest: it describes where airlock
    /// looks, not what the rule means.
    #[must_use]
    pub fn observation(&self) -> Observation {
        match self.id {
            // Org placement and repository naming are platform identity.
            "REPO-ORG-01" | "REPO-ORG-02" | "REPO-NAME-01" | "REPO-NAME-02" | "REPO-NAME-03"
            | "REPO-NAME-04"
            // Live metadata against the declared file needs the live half.
            | "REPO-META-13"
            // Branch, ruleset, merge-setting, feature, tag, history, and
            // credential-naming facts are all API-owned. REPO-GIT-13 is the
            // exception: it reads workflow text.
            | "REPO-GIT-01" | "REPO-GIT-02" | "REPO-GIT-03" | "REPO-GIT-04" | "REPO-GIT-05"
            | "REPO-GIT-06" | "REPO-GIT-07" | "REPO-GIT-08" | "REPO-GIT-09" | "REPO-GIT-10"
            | "REPO-GIT-14" => Observation::Platform,
            _ => Observation::FileTree,
        }
    }
}

/// The registry content digest.
///
/// SHA-256 over the sorted `(id, statement, severity, evaluation,
/// evaluation reason, applicability)` tuples, so
/// two binaries that agree on the digest agree on what every rule means. It
/// travels in every audit result.
#[must_use]
pub fn digest() -> String {
    let mut tuples: Vec<String> = CHECKS
        .iter()
        .map(|check| {
            format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                check.id,
                check.statement,
                check.severity.code(),
                check.evaluation.code(),
                check.evaluation_reason().unwrap_or_default(),
                check.applicability().code()
            )
        })
        .collect();
    tuples.sort();

    let mut hasher = Sha256::new();
    for tuple in tuples {
        hasher.update(tuple.as_bytes());
        hasher.update(b"\x1e");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_check_definition_id_is_unique() {
        let ids: BTreeSet<&str> = CHECKS.iter().map(|check| check.id).collect();
        assert_eq!(ids.len(), CHECKS.len());
    }

    #[test]
    fn only_release_unit_rules_have_built_in_applicability() {
        let conditioned: Vec<&str> = CHECKS
            .iter()
            .filter(|check| check.applicability() != Applicability::Always)
            .map(|check| check.id)
            .collect();
        assert_eq!(conditioned, ["REPO-LIC-04", "REPO-GIT-09", "REPO-TASK-04"]);
    }

    #[test]
    fn platform_rules_are_exactly_the_api_owned_facts() {
        let platform: Vec<&str> = CHECKS
            .iter()
            .filter(|check| check.observation() == Observation::Platform)
            .map(|check| check.id)
            .collect();
        assert_eq!(
            platform,
            [
                "REPO-ORG-01",
                "REPO-ORG-02",
                "REPO-NAME-01",
                "REPO-NAME-02",
                "REPO-NAME-03",
                "REPO-NAME-04",
                "REPO-META-13",
                "REPO-GIT-01",
                "REPO-GIT-02",
                "REPO-GIT-03",
                "REPO-GIT-14",
                "REPO-GIT-04",
                "REPO-GIT-05",
                "REPO-GIT-06",
                "REPO-GIT-07",
                "REPO-GIT-08",
                "REPO-GIT-09",
                "REPO-GIT-10",
            ]
        );
    }

    #[test]
    fn every_check_definition_has_a_statement() {
        for check in CHECKS {
            assert!(!check.statement.trim().is_empty(), "{}", check.id);
        }
    }

    #[test]
    fn the_digest_is_stable_and_prefixed() {
        let first = digest();
        assert!(first.starts_with("sha256:"));
        assert_eq!(first, digest());
    }

    #[test]
    fn sections_round_trip_through_their_codes() {
        for section in Section::ALL {
            assert_eq!(Section::parse(section.code()), Some(*section));
        }
    }

    #[test]
    fn severities_round_trip_through_their_codes() {
        for severity in Severity::ALL {
            assert_eq!(Severity::parse(severity.code()), Some(*severity));
        }
    }

    #[test]
    fn every_section_has_at_least_one_rule() {
        for section in Section::ALL {
            assert!(!in_section(*section).is_empty(), "{section}");
        }
    }

    #[test]
    fn declared_parameters_belong_to_mechanical_rules() {
        for check in CHECKS {
            if !check.params.is_empty() {
                assert_eq!(check.evaluation, Evaluation::Mechanical, "{}", check.id);
            }
        }
    }
}
