//! REPO-LIC-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-05",
    statement:
        "A plumbing repository's README states that the license covers packaging, not payload",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Read the README",
    remediation: remediation(
        "state-packaging-license-scope",
        "REPO-LIC-05",
        Lane::JudgmentFile,
        "State in the README that the licence covers packaging, not payload.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
