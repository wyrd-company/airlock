//! REPO-ORG-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-ORG-02",
    statement: "A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company`",
    severity: Severity::Observation,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Judgment",
    remediation: not_remediable(
        "REPO-ORG-02",
        "Satisfied by a human's considered judgment; there is no artifact to change.",
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
