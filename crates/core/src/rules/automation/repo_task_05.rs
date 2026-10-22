//! REPO-TASK-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TASK-05",
    statement: "Every include sets `dir:`",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Root `taskfile.yml`",
    fix: fix(
        "set-include-dirs",
        "REPO-TASK-05",
        FixKind::Airlock,
        "Set `dir:` on every taskfile include.",
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
    unbuilt_reason: None,
};
