//! REPO-PROP-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-PROP-04",
    statement: "No workflow writes organization custom properties",
    severity: Severity::Blocking,
    section: Section::Classification,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
