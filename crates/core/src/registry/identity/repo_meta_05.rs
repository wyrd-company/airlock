//! REPO-META-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-05",
    statement: "The description agrees with the README's opening line",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare",
    remediation: remediation(
        "align-description-and-readme",
        "REPO-META-05",
        Lane::JudgmentFile,
        "Align the declared description with the README's opening line.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
