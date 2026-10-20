//! REPO-GIT-08.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-08",
    statement: "Tags carry no `v` prefix",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`git tag`",
    remediation: not_remediable(
        "REPO-GIT-08",
        "Closing it means deleting and recreating published tags — history surgery airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
