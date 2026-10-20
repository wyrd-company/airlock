//! REPO-LIC-06.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-06",
    statement:
        "A non-default license choice has a stated reason in the README or a decision record",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Read",
    fix: fix(
        "record-license-choice-reason",
        "REPO-LIC-06",
        FixKind::Agent,
        "Record the reason for the non-default licence in the README or a decision record.",
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
