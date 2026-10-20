//! REPO-LIC-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-05",
    statement:
        "A plumbing repository's README states that the license covers packaging, not payload",
    severity: Severity::Required,
    section: Section::Licensing,
    evaluation: Evaluation::Manual,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
