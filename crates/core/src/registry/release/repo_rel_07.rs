//! REPO-REL-07.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-07",
    statement: "No workflow publishes automatically on merge",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "remove-merge-publish",
        "REPO-REL-07",
        Lane::JudgmentFile,
        "Remove any workflow that publishes automatically on merge.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
