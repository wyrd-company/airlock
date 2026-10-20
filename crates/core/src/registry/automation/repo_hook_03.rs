//! REPO-HOOK-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-03",
    statement: "`pre-push` runs nothing or lint only",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-pre-push-hook",
        "REPO-HOOK-03",
        Lane::DeterministicFile,
        "Configure `pre-push` to run nothing or lint only.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
