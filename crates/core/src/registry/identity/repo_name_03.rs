//! REPO-NAME-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-03",
    statement: "A repository in a product family carries the family prefix",
    severity: Severity::Observation,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Repository name",
    remediation: remediation(
        "rename-repository-family-prefix",
        "REPO-NAME-03",
        Lane::OperatorSetting,
        "Rename the repository to carry its product family prefix.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
