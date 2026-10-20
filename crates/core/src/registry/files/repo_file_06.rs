//! REPO-FILE-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-06",
    statement: "`taskfile.yml` exists, lowercase",
    severity: Severity::Required,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-taskfile",
        "REPO-FILE-06",
        Lane::JudgmentFile,
        "Add a lowercase `taskfile.yml` wired to this repository's toolchain.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
