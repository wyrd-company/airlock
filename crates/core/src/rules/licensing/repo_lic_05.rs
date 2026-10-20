//! REPO-LIC-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-05",
    statement:
        "A plumbing repository's README states that the license covers packaging, not payload",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Read the README",
    fix: fix(
        "state-packaging-license-scope",
        "REPO-LIC-05",
        FixKind::Agent,
        "State in the README that the licence covers packaging, not payload.",
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
