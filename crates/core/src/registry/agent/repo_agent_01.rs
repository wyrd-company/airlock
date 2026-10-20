//! REPO-AGENT-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-01",
    statement: "`AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live",
    severity: Severity::Required,
    section: Section::Agent,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "write-agents-coverage",
        "REPO-AGENT-01",
        Lane::JudgmentFile,
        "Cover in `AGENTS.md` what the repository is, commands by reference, conventions, what not to touch, and where docs live.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
