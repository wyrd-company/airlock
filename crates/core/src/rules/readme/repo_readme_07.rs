//! REPO-README-07.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-README-07",
    statement: "Prerequisites appear only where non-obvious",
    severity: Severity::Advisory,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    fix: fix(
        "trim-prerequisites",
        "REPO-README-07",
        FixKind::Agent,
        "Trim prerequisites to the non-obvious.",
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
