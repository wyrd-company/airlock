//! REPO-REL-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-04",
    statement: "Release is `workflow_dispatch` on a pinned source SHA",
    severity: Severity::Blocking,
    section: Section::Release,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "redesign-release-trigger",
        "REPO-REL-04",
        Lane::JudgmentFile,
        "Make release a `workflow_dispatch` on a pinned source SHA.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
