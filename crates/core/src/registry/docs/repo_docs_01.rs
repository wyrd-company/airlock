//! REPO-DOCS-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-01",
    statement: "User-facing pages sit at the top level of `docs/`",
    severity: Severity::Observation,
    section: Section::Docs,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Directory listing",
    remediation: remediation(
        "move-user-facing-docs",
        "REPO-DOCS-01",
        Lane::JudgmentFile,
        "Move user-facing pages to the top level of `docs/`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
