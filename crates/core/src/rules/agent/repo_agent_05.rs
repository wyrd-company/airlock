//! REPO-AGENT-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-AGENT-05",
    statement: "Generated directories are marked `linguist-generated=true` in `.gitattributes`",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "mark-generated-directories",
        "REPO-AGENT-05",
        FixKind::Agent,
        "Mark generated directories `linguist-generated=true` in `.gitattributes`.",
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
