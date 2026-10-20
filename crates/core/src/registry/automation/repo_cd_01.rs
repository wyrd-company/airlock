//! REPO-CD-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-01",
    statement: "A repository that delivers anything has `.github/workflows/cd.yml`",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-cd-workflow",
        "REPO-CD-01",
        Lane::JudgmentFile,
        "Add a `.github/workflows/cd.yml` delivering what this repository ships.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
