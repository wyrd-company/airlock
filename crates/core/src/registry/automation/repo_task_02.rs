//! REPO-TASK-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-02",
    statement: "Applicability of `build` and `dev` was an explicit decision, and they exist where applicable",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "`task --list-all` plus the recorded decision",
    remediation: remediation(
        "decide-build-and-dev-tasks",
        "REPO-TASK-02",
        Lane::JudgmentFile,
        "Decide whether `build` and `dev` apply, and add them where they do.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
