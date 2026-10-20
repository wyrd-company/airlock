//! REPO-META-08.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-08",
    statement: "A repository in a product family carries the family topic",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare against `topics.md`",
    fix: fix(
        "add-family-topic",
        "REPO-META-08",
        FixKind::Agent,
        "Add the product family topic to the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
