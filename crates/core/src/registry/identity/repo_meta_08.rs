//! REPO-META-08.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-08",
    statement: "A repository in a product family carries the family topic",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: remediation(
        "add-family-topic",
        "REPO-META-08",
        Lane::JudgmentFile,
        "Add the product family topic to the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
