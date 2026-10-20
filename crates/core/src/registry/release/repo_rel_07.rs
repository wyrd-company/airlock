//! REPO-REL-07.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-07",
    statement: "No workflow publishes automatically on merge",
    severity: Severity::Blocking,
    section: Section::Release,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
