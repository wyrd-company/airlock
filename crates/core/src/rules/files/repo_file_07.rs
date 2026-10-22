//! REPO-FILE-07.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-07",
    statement: "`.github/workflows/` contains at least a CI workflow triggered on pull request",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "add-ci-workflow",
        "REPO-FILE-07",
        FixKind::Airlock,
        "Add the CI workflow required by the rule: triggered on pull request, running `task check`.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
