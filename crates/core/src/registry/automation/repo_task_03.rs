//! REPO-TASK-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-03",
    statement: "`task check` runs everything CI runs",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare taskfile against workflows",
    remediation: remediation(
        "align-check-with-ci",
        "REPO-TASK-03",
        Lane::JudgmentFile,
        "Make `task check` run everything CI runs.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
