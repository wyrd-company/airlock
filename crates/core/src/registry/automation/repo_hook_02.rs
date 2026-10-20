//! REPO-HOOK-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-02",
    statement: "`commit-msg` validates conventional commit format",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-commit-msg-hook",
        "REPO-HOOK-02",
        Lane::DeterministicFile,
        "Configure `commit-msg` to validate conventional commit format.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
