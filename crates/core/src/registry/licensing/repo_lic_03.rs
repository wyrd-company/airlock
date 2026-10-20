//! REPO-LIC-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-03",
    statement: "The repository is not dual-licensed `MIT OR Apache-2.0`",
    severity: Severity::Blocking,
    section: Section::Licensing,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`LICENSE`, package metadata",
    remediation: remediation(
        "replace-dual-license",
        "REPO-LIC-03",
        Lane::JudgmentFile,
        "Replace the dual `MIT OR Apache-2.0` licence with the single licence the category calls for.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
