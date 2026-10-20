//! REPO-PROP-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-PROP-04",
    statement: "No workflow writes organization custom properties",
    severity: Severity::Blocking,
    section: Section::Classification,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "remove-property-writing-workflows",
        "REPO-PROP-04",
        Lane::JudgmentFile,
        "Remove workflow steps that write organization custom properties.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
