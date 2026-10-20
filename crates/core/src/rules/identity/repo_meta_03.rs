//! REPO-META-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-03",
    statement: "The description expands any acronym on first use",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Read it",
    fix: fix(
        "expand-description-acronyms",
        "REPO-META-03",
        FixKind::Agent,
        "Rewrite the declared description to expand each acronym on first use.",
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
