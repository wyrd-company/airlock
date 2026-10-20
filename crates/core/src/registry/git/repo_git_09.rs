//! REPO-GIT-09.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-09",
    statement: "Multi-release-unit tags use `@scope/name@version`",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`git tag`",
    remediation: not_remediable(
        "REPO-GIT-09",
        "Closing it means re-tagging published releases — history surgery airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::ReleaseUnitsDeclared,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
