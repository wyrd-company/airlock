//! REPO-TASK-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-01",
    statement: "`test`, `lint`, `format`, and `check` tasks exist",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`task --list-all`",
    remediation: remediation(
        "add-core-tasks",
        "REPO-TASK-01",
        Lane::JudgmentFile,
        "Add `test`, `lint`, `format`, and `check` tasks wired to this repository's toolchain.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
