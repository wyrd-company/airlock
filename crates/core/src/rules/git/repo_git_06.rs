//! REPO-GIT-06.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, RuleDefinition, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-06",
    statement: "Auto-delete head branch on merge is enabled",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json deleteBranchOnMerge`",
    fix: fix(
        "enable-head-branch-auto-delete",
        "REPO-GIT-06",
        FixKind::Operator,
        "Enable auto-delete of head branches on merge.",
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
