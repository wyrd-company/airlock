//! REPO-AGENT-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-AGENT-03",
    statement: "`AGENTS.md` does not restate the README or `CONTRIBUTING.md`",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Compare",
    fix: fix(
        "deduplicate-agents-content",
        "REPO-AGENT-03",
        FixKind::Agent,
        "Remove `AGENTS.md` content that restates the README or `CONTRIBUTING.md`.",
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
