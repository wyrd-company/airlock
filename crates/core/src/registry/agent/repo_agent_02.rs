//! REPO-AGENT-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-02",
    statement: "`AGENTS.md` contains nothing discoverable by reading the repository",
    severity: Severity::Required,
    section: Section::Agent,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "remove-discoverable-agents-content",
        "REPO-AGENT-02",
        Lane::JudgmentFile,
        "Remove from `AGENTS.md` anything discoverable by reading the repository.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
