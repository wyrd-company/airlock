//! REPO-CI-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-04",
    statement: "Every action is pinned to a full commit SHA with a version comment",
    severity: Severity::Blocking,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "pin-actions-to-shas",
        "REPO-CI-04",
        Lane::DeterministicFile,
        "Pin every action to a full commit SHA with a version comment.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
