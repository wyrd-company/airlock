//! REPO-GIT-14.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-14",
    statement: "No secret or variable is named after the task that introduced it",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "Workflow source",
    fix: fix(
        "rename-task-named-credentials",
        "REPO-GIT-14",
        FixKind::Operator,
        "Rename secrets and variables after what they are, not the task that introduced them.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
