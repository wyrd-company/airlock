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
    guidance: "Compare declared topics with the organization-owned family topic. Family membership is declared; topic similarity and a shared name prefix do not establish it.",
    fix: fix(
        "add-family-topic",
        "REPO-META-08",
        FixKind::Agent,
        "Add the product family topic to the declared topics.",
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
    unbuilt_reason: Some("The compiled check is not built yet"),
};
