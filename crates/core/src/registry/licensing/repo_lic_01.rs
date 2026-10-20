//! REPO-LIC-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-01",
    statement: "A `LICENSE` file exists",
    severity: Severity::Blocking,
    section: Section::Licensing,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-license-file",
        "REPO-LIC-01",
        Lane::DeterministicFile,
        "Add a `LICENSE` file carrying the default Apache-2.0 licence; a category-specific licence is REPO-LIC-02's judgment.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
