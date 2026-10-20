//! REPO-AGENT-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-03",
    statement: "`AGENTS.md` does not restate the README or `CONTRIBUTING.md`",
    severity: Severity::Required,
    section: Section::Agent,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Compare",
    remediation: remediation(
        "deduplicate-agents-content",
        "REPO-AGENT-03",
        Lane::JudgmentFile,
        "Remove `AGENTS.md` content that restates the README or `CONTRIBUTING.md`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
