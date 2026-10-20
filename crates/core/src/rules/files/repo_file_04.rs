//! REPO-FILE-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-04",
    statement: "`.gitattributes` exists and normalizes line endings",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "add-gitattributes",
        "REPO-FILE-04",
        FixKind::Airlock,
        "Add a `.gitattributes` that normalises line endings.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
