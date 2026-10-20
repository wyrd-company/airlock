//! REPO-README-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-README-04",
    statement: "A quickstart or usage section contains at least one real, runnable example",
    severity: Severity::Blocking,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    fix: fix(
        "write-quickstart-section",
        "REPO-README-04",
        FixKind::Agent,
        "Write a quickstart with at least one real, runnable example.",
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
