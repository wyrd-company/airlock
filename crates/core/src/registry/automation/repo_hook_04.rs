//! REPO-HOOK-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-04",
    statement: "Hooks invoke tasks rather than raw commands",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "invoke-tasks-from-hooks",
        "REPO-HOOK-04",
        Lane::JudgmentFile,
        "Point hooks at tasks instead of raw commands.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
