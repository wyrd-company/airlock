//! REPO-HOOK-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-HOOK-01",
    statement: "`pre-commit` runs `format` and `lint` on staged files only",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    fix: fix(
        "configure-pre-commit-hook",
        "REPO-HOOK-01",
        FixKind::Airlock,
        "Configure `pre-commit` to run `format` and `lint` on staged files only.",
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
    unbuilt_reason: Some("A remaining requirement has no compiled check yet"),
};
