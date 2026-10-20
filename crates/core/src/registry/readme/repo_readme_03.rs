//! REPO-README-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-03",
    statement: "An installation section covers every supported channel",
    severity: Severity::Blocking,
    section: Section::Readme,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare against published channels",
    remediation: remediation(
        "write-install-section",
        "REPO-README-03",
        Lane::JudgmentFile,
        "Write an installation section covering every supported channel.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
