//! REPO-CD-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CD-01",
    statement: "A repository that delivers anything has `.github/workflows/cd.yml`",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "File presence",
    fix: fix(
        "add-cd-workflow",
        "REPO-CD-01",
        FixKind::Agent,
        "Add a `.github/workflows/cd.yml` delivering what this repository ships.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
