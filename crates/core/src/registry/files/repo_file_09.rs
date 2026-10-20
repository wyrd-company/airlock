//! REPO-FILE-09.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-09",
    statement: "`.config/lefthook.yml` exists",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-lefthook-config",
        "REPO-FILE-09",
        Lane::DeterministicFile,
        "Add the standard `.config/lefthook.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
