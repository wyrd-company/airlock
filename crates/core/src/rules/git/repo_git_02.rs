//! REPO-GIT-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-02",
    statement: "The repository is covered by organization-sourced rulesets on its default branch",
    severity: Severity::Blocking,
    section: Section::Git,
    params: &[],
    guidance: "`gh api repos/{o}/{r}/rulesets?includes_parents=true`",
    fix: fix(
        "attach-org-rulesets",
        "REPO-GIT-02",
        FixKind::Operator,
        "Attach organization-sourced rulesets to the default branch.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
