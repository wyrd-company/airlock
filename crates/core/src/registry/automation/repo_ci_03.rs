//! REPO-CI-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-03",
    statement: "Every job declares only the permissions it needs",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "scope-job-permissions",
        "REPO-CI-03",
        Lane::JudgmentFile,
        "Declare on each job only the permissions it needs.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
