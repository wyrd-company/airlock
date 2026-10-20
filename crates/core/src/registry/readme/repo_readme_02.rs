//! REPO-README-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-02",
    statement: "Badges are present",
    severity: Severity::Required,
    section: Section::Readme,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "add-readme-badges",
        "REPO-README-02",
        Lane::JudgmentFile,
        "Add badges to the README.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
