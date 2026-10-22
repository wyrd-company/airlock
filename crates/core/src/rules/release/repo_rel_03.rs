//! REPO-REL-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-REL-03",
    statement: "A multi-unit repository has no root aggregate changelog",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "remove-root-changelog",
        "REPO-REL-03",
        FixKind::Airlock,
        "Remove the root aggregate changelog.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
