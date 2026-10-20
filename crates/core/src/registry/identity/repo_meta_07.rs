//! REPO-META-07.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-07",
    statement: "Topics include at least one artifact-type and one ecosystem term",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: remediation(
        "add-artifact-and-ecosystem-topics",
        "REPO-META-07",
        Lane::JudgmentFile,
        "Add an artifact-type and an ecosystem term to the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
