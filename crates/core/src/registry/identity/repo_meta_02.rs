//! REPO-META-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-02",
    statement:
        "The description is one sentence, at most 160 characters, and survives truncation at ~80",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "rewrite-description-length",
        "REPO-META-02",
        Lane::JudgmentFile,
        "Rewrite the declared description as one sentence within the length budget.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
