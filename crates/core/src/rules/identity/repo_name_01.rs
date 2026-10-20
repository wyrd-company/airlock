//! REPO-NAME-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-NAME-01",
    statement: "The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Repository name",
    fix: fix(
        "rename-repository-kebab",
        "REPO-NAME-01",
        FixKind::Operator,
        "Rename the repository to lower-kebab-case.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
