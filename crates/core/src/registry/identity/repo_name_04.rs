//! REPO-NAME-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-04",
    statement: "The family prefix and the family topic agree",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Name vs topics",
    remediation: remediation(
        "align-family-prefix-and-topic",
        "REPO-NAME-04",
        Lane::JudgmentFile,
        "Align the declared family topic with the name's family prefix.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
