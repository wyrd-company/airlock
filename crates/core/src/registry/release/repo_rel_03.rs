//! REPO-REL-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-03",
    statement: "A multi-unit repository has no root aggregate changelog",
    severity: Severity::Required,
    section: Section::Release,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "remove-root-changelog",
        "REPO-REL-03",
        Lane::DeterministicFile,
        "Remove the root aggregate changelog.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
