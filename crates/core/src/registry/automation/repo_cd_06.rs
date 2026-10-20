//! REPO-CD-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-06",
    statement: "CD asserts every required publication credential is present before doing any work",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-credentials-up-front",
        "REPO-CD-06",
        Lane::JudgmentFile,
        "Assert every required publication credential before CD does any work.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
