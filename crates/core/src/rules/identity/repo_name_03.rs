//! REPO-NAME-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-NAME-03",
    statement: "A repository in a product family carries the family prefix",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Read the organization-owned family declaration and compare the repository name with its family prefix. A family topic may have a distinct prefix; do not infer an alias from initials.",
    fix: fix(
        "rename-repository-family-prefix",
        "REPO-NAME-03",
        FixKind::Operator,
        "Rename the repository to carry its product family prefix.",
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
