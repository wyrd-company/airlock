//! REPO-CI-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-06",
    statement: "A `concurrency` group with `cancel-in-progress` covers pull requests",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "add-ci-concurrency-group",
        "REPO-CI-06",
        Lane::DeterministicFile,
        "Add a `concurrency` group with `cancel-in-progress` covering pull requests.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
