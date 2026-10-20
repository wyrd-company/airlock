//! REPO-CI-10.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-10",
    statement: "No workflow mutates repository settings",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "remove-workflow-settings-writes",
        "REPO-CI-10",
        Lane::JudgmentFile,
        "Remove repository-settings mutations from every workflow.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
