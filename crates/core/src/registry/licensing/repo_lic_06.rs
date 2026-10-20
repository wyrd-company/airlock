//! REPO-LIC-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-06",
    statement:
        "A non-default license choice has a stated reason in the README or a decision record",
    severity: Severity::Observation,
    section: Section::Licensing,
    evaluation: Evaluation::Manual,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
