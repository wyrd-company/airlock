//! REPO-AGENT-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-04",
    statement: "`CONTRIBUTING.md` contains no command sequences beyond `task check`",
    severity: Severity::Required,
    section: Section::Agent,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "trim-contributing-commands",
        "REPO-AGENT-04",
        Lane::JudgmentFile,
        "Trim `CONTRIBUTING.md` command sequences down to `task check`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
