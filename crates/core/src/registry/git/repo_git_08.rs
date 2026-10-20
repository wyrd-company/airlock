//! REPO-GIT-08.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-08",
    statement: "Tags carry no `v` prefix",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`git tag`",
    remediation: not_remediable(
        "REPO-GIT-08",
        "Closing it means deleting and recreating published tags — history surgery airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
