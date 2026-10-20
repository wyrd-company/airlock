//! REPO-META-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-04",
    statement: "The description contains no self-deprecation",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Read it",
    fix: fix(
        "remove-description-self-deprecation",
        "REPO-META-04",
        FixKind::Agent,
        "Rewrite the declared description without self-deprecation.",
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
