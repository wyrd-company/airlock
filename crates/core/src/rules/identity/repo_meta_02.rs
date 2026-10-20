//! REPO-META-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-02",
    statement:
        "The description is one sentence, at most 160 characters, and survives truncation at ~80",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "rewrite-description-length",
        "REPO-META-02",
        FixKind::Agent,
        "Rewrite the declared description as one sentence within the length budget.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("A remaining requirement has no compiled check yet"),
};
