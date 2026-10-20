//! REPO-NAME-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-01",
    statement: "The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Repository name",
    remediation: remediation(
        "rename-repository-kebab",
        "REPO-NAME-01",
        Lane::OperatorSetting,
        "Rename the repository to lower-kebab-case.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
