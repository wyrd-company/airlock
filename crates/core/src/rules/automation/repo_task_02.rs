//! REPO-TASK-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TASK-02",
    statement: "of `build` and `dev` was an explicit decision, and they exist where applicable",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`task --list-all` plus the recorded decision",
    fix: fix(
        "decide-build-and-dev-tasks",
        "REPO-TASK-02",
        FixKind::Agent,
        "Decide whether `build` and `dev` apply, and add them where they do.",
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
    unbuilt_reason: Some("The compiled check is not built yet"),
};
