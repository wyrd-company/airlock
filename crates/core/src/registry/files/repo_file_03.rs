//! REPO-FILE-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-03",
    statement: "`.gitignore` exists and is ecosystem-appropriate",
    severity: Severity::Required,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-gitignore",
        "REPO-FILE-03",
        Lane::JudgmentFile,
        "Add an ecosystem-appropriate `.gitignore`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
