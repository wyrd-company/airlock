//! REPO-META-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-05",
    statement: "The description agrees with the README's opening line",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare",
    fix: fix(
        "align-description-and-readme",
        "REPO-META-05",
        FixKind::Agent,
        "Align the declared description with the README's opening line.",
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
