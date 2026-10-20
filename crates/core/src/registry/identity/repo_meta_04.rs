//! REPO-META-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-04",
    statement: "The description contains no self-deprecation",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read it",
    remediation: remediation(
        "remove-description-self-deprecation",
        "REPO-META-04",
        Lane::JudgmentFile,
        "Rewrite the declared description without self-deprecation.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
