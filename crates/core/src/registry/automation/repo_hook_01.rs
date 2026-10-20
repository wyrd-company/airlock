//! REPO-HOOK-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-01",
    statement: "`pre-commit` runs `format` and `lint` on staged files only",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-pre-commit-hook",
        "REPO-HOOK-01",
        Lane::DeterministicFile,
        "Configure `pre-commit` to run `format` and `lint` on staged files only.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
