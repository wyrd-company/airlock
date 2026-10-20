//! REPO-GIT-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, RuleDefinition, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-04",
    statement: "Merge commits are disabled",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json mergeCommitAllowed`",
    fix: fix(
        "disable-merge-commits",
        "REPO-GIT-04",
        FixKind::Operator,
        "Disable merge commits in the live repository settings.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
