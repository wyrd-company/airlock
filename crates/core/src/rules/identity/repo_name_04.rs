//! REPO-NAME-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-NAME-04",
    statement: "The family prefix and the family topic agree",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Name vs topics",
    fix: fix(
        "align-family-prefix-and-topic",
        "REPO-NAME-04",
        FixKind::Agent,
        "Align the declared family topic with the name's family prefix.",
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
