//! REPO-DOCS-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-02",
    statement: "Engineering artifacts sit in `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`",
    severity: Severity::Observation,
    section: Section::Docs,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Directory listing",
    remediation: remediation(
        "move-engineering-artifacts",
        "REPO-DOCS-02",
        Lane::JudgmentFile,
        "Move engineering artifacts into `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
