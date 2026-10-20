//! REPO-LIC-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-02",
    statement: "The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license",
    severity: Severity::Required,
    section: Section::Licensing,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Judgment against the category table",
    remediation: remediation(
        "replace-license",
        "REPO-LIC-02",
        Lane::JudgmentFile,
        "Replace the licence with the one the repository's category calls for.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
