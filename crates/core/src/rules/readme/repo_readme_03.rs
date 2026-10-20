//! REPO-README-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-README-03",
    statement: "An installation section covers every supported channel",
    severity: Severity::Blocking,
    section: Section::Readme,
    params: &[],
    guidance: "Compare against published channels",
    fix: fix(
        "write-install-section",
        "REPO-README-03",
        FixKind::Agent,
        "Write an installation section covering every supported channel.",
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
