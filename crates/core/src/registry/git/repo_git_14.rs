//! REPO-GIT-14.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-14",
    statement: "No secret or variable is named after the task that introduced it",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Workflow source",
    remediation: remediation(
        "rename-task-named-credentials",
        "REPO-GIT-14",
        Lane::OperatorSetting,
        "Rename secrets and variables after what they are, not the task that introduced them.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
