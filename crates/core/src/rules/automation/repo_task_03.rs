//! REPO-TASK-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TASK-03",
    statement: "`task check` runs everything CI runs",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Compare taskfile against workflows",
    fix: fix(
        "align-check-with-ci",
        "REPO-TASK-03",
        FixKind::Agent,
        "Make `task check` run everything CI runs.",
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
