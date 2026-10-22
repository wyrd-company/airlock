//! REPO-AGENT-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-AGENT-04",
    statement: "`CONTRIBUTING.md` contains no command sequences beyond `task check`",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    fix: fix(
        "trim-contributing-commands",
        "REPO-AGENT-04",
        FixKind::Agent,
        "Trim `CONTRIBUTING.md` command sequences down to `task check`.",
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
