//! REPO-LIC-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-01",
    statement: "A `LICENSE` file exists",
    severity: Severity::Blocking,
    section: Section::Licensing,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "add-license-file",
        "REPO-LIC-01",
        FixKind::Airlock,
        "Add a `LICENSE` file carrying the default Apache-2.0 licence; a category-specific licence is REPO-LIC-02's judgment.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
