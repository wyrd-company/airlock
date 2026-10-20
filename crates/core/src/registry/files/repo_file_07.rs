//! REPO-FILE-07.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-07",
    statement: "`.github/workflows/` contains at least a CI workflow triggered on pull request",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-ci-workflow",
        "REPO-FILE-07",
        Lane::DeterministicFile,
        "Add the standard CI workflow: triggered on pull request, running `task check`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
