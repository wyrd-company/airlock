//! REPO-FILE-15.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-15",
    statement: "Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs",
    severity: Severity::Observation,
    section: Section::Files,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare against the org `.github` repository",
    remediation: remediation(
        "remove-duplicated-health-files",
        "REPO-FILE-15",
        Lane::JudgmentFile,
        "Remove community health files the org already provides, unless the local copy is deliberate.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
