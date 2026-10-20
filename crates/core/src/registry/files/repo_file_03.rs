//! REPO-FILE-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-03",
    statement: "`.gitignore` exists and is ecosystem-appropriate",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-gitignore",
        "REPO-FILE-03",
        Lane::JudgmentFile,
        "Add an ecosystem-appropriate `.gitignore`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
