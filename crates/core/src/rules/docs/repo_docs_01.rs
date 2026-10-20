//! REPO-DOCS-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-DOCS-01",
    statement: "User-facing pages sit at the top level of `docs/`",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "Directory listing",
    fix: fix(
        "move-user-facing-docs",
        "REPO-DOCS-01",
        FixKind::Agent,
        "Move user-facing pages to the top level of `docs/`.",
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
