//! REPO-CI-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-01",
    statement: "CI is triggered on `pull_request`",
    severity: Severity::Blocking,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "add-pull-request-trigger",
        "REPO-CI-01",
        Lane::DeterministicFile,
        "Add a `pull_request` trigger to the CI workflow.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
