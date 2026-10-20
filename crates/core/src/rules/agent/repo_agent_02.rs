//! REPO-AGENT-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-AGENT-02",
    statement: "`AGENTS.md` contains nothing discoverable by reading the repository",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    fix: fix(
        "remove-discoverable-agents-content",
        "REPO-AGENT-02",
        FixKind::Agent,
        "Remove from `AGENTS.md` anything discoverable by reading the repository.",
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
