//! REPO-FILE-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-01",
    statement: "`README.md` exists",
    severity: Severity::Blocking,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-readme",
        "REPO-FILE-01",
        Lane::JudgmentFile,
        "Write a `README.md` for this repository.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
