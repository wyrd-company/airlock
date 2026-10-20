//! REPO-README-09.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-09",
    statement: "No contributing section",
    severity: Severity::Required,
    section: Section::Readme,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "remove-contributing-section",
        "REPO-README-09",
        Lane::JudgmentFile,
        "Remove the README's contributing section.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
