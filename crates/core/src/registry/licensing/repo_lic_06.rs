//! REPO-LIC-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-06",
    statement:
        "A non-default license choice has a stated reason in the README or a decision record",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "record-license-choice-reason",
        "REPO-LIC-06",
        Lane::JudgmentFile,
        "Record the reason for the non-default licence in the README or a decision record.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
