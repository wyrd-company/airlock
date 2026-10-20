//! REPO-README-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-05",
    statement: "A repository with a user interface has an animated demo",
    severity: Severity::Observation,
    section: Section::Readme,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "add-animated-demo",
        "REPO-README-05",
        Lane::JudgmentFile,
        "Record and embed an animated demo.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
