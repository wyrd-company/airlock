//! REPO-REL-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-05",
    statement: "The release workflow asserts the pinned SHA equals current `main`",
    severity: Severity::Blocking,
    section: Section::Release,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-sha-is-main",
        "REPO-REL-05",
        Lane::JudgmentFile,
        "Assert in the release workflow that the pinned SHA equals current `main`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
