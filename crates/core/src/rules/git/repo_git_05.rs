//! REPO-GIT-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, RuleDefinition, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-05",
    statement: "Squash merge is enabled",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json squashMergeAllowed`",
    fix: fix(
        "enable-squash-merge",
        "REPO-GIT-05",
        FixKind::Operator,
        "Enable squash merge in the live repository settings.",
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
