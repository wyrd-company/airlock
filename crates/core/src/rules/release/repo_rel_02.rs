//! REPO-REL-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-REL-02",
    statement: "A `CHANGELOG.md` exists at each release unit's declared path",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "Compare against `.intentional/config.yml`",
    fix: fix(
        "add-unit-changelogs",
        "REPO-REL-02",
        FixKind::Airlock,
        "Add a `CHANGELOG.md` skeleton at each release unit's declared path.",
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
