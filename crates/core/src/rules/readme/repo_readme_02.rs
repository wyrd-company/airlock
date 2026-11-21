//! REPO-README-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-README-02",
    statement: "Badges are present",
    severity: Severity::Advisory,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    fix: fix(
        "add-readme-badges",
        "REPO-README-02",
        FixKind::Agent,
        "Add badges to the README.",
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
