//! REPO-REL-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-01",
    statement: "`.intentional/config.yml` exists and declares release units",
    severity: Severity::Required,
    section: Section::Release,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "declare-release-units",
        "REPO-REL-01",
        Lane::JudgmentFile,
        "Add `.intentional/config.yml` declaring this repository's release units.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
