//! REPO-TASK-06.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TASK-06",
    statement: "Include namespaces match release unit ids",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Compare against `.intentional/config.yml`",
    fix: fix(
        "align-include-namespaces",
        "REPO-TASK-06",
        FixKind::Airlock,
        "Rename include namespaces to match release unit ids.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
