//! REPO-HOOK-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-HOOK-02",
    statement: "`commit-msg` validates conventional commit format",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    fix: fix(
        "configure-commit-msg-hook",
        "REPO-HOOK-02",
        FixKind::Airlock,
        "Configure `commit-msg` to validate conventional commit format.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
