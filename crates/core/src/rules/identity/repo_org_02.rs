//! REPO-ORG-02.
//
// relationships:
//   references: rules

use crate::fix::not_fixable;
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-ORG-02",
    statement: "A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company`",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Judgment",
    fix: not_fixable(
        "REPO-ORG-02",
        "Satisfied by a human's considered judgment; there is no artifact to change.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
