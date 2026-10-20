//! REPO-CI-08.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-08",
    statement: "A required check validates pull request title format",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents and ruleset",
    remediation: remediation(
        "add-title-check",
        "REPO-CI-08",
        Lane::DeterministicFile,
        "Add the standard pull request title check workflow; marking it required is the rulesets' operator work.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
