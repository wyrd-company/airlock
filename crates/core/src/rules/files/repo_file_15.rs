//! REPO-FILE-15.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-15",
    statement: "Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "Compare against the org `.github` repository",
    fix: fix(
        "remove-duplicated-health-files",
        "REPO-FILE-15",
        FixKind::Agent,
        "Remove community health files the org already provides, unless the local copy is deliberate.",
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
