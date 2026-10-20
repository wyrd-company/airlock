//! REPO-META-13.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, RuleDefinition, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-13",
    statement: "Live GitHub metadata matches the declared file",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "`gh repo view` vs file — drift means reconciliation is not running",
    fix: fix(
        "align-live-settings",
        "REPO-META-13",
        FixKind::Operator,
        "Align live GitHub metadata to the declared file.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
