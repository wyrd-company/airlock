//! REPO-TASK-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TASK-01",
    statement: "`test`, `lint`, `format`, and `check` tasks exist",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`task --list-all`",
    fix: fix(
        "add-core-tasks",
        "REPO-TASK-01",
        FixKind::Agent,
        "Add `test`, `lint`, `format`, and `check` tasks wired to this repository's toolchain.",
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
