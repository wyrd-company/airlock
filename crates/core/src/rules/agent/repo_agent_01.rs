//! REPO-AGENT-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-AGENT-01",
    statement: "`AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    fix: fix(
        "write-agents-coverage",
        "REPO-AGENT-01",
        FixKind::Agent,
        "Cover in `AGENTS.md` what the repository is, commands by reference, conventions, what not to touch, and where docs live.",
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
