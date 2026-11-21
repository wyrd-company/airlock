//! REPO-REL-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-REL-01",
    statement: "`.intentional/config.yml` exists and declares release units",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "declare-release-units",
        "REPO-REL-01",
        FixKind::Agent,
        "Add `.intentional/config.yml` declaring this repository's release units.",
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
