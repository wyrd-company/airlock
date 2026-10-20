//! REPO-GIT-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-03",
    statement: "Those rulesets require pull requests, allow only squash and rebase, and require linear history",
    severity: Severity::Blocking,
    section: Section::Git,
    params: &[],
    guidance: "`gh api repos/{o}/{r}/rules/branches/main`",
    fix: fix(
        "tighten-org-rulesets",
        "REPO-GIT-03",
        FixKind::Operator,
        "Configure the rulesets to require pull requests, allow only squash and rebase, and require linear history.",
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
    disclosure_gate: None,
    unbuilt_reason: None,
};
