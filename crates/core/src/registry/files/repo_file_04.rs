//! REPO-FILE-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-04",
    statement: "`.gitattributes` exists and normalizes line endings",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "add-gitattributes",
        "REPO-FILE-04",
        Lane::DeterministicFile,
        "Add a `.gitattributes` that normalises line endings.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
