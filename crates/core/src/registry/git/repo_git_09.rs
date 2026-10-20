//! REPO-GIT-09.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-09",
    statement: "Multi-release-unit tags use `@scope/name@version`",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`git tag`",
    remediation: not_remediable(
        "REPO-GIT-09",
        "Closing it means re-tagging published releases — history surgery airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
