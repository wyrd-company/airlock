//! REPO-FILE-16.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-16",
    statement: "`.github/airlock.yml` exists",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "add-repo-settings",
        "REPO-FILE-16",
        FixKind::Agent,
        "Add `.github/airlock.yml` declaring this repository's metadata.",
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
    unbuilt_reason: None,
};
