//! REPO-REL-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-06",
    statement: "The release workflow asserts a successful push-event CI run for exactly that SHA",
    severity: Severity::Blocking,
    section: Section::Release,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-ci-passed-for-sha",
        "REPO-REL-06",
        Lane::JudgmentFile,
        "Assert in the release workflow a successful push-event CI run for exactly that SHA.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
