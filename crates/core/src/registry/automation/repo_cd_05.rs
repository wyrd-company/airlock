//! REPO-CD-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-05",
    statement:
        "A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release",
    severity: Severity::Blocking,
    section: Section::Automation,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Dispatch inputs and their use",
    remediation: remediation(
        "restrict-dispatch-to-redelivery",
        "REPO-CD-05",
        Lane::JudgmentFile,
        "Restrict the CD `workflow_dispatch` to re-delivering an existing tag.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
