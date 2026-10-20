//! REPO-AGENT-05.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-05",
    statement: "Generated directories are marked `linguist-generated=true` in `.gitattributes`",
    severity: Severity::Required,
    section: Section::Agent,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "mark-generated-directories",
        "REPO-AGENT-05",
        Lane::JudgmentFile,
        "Mark generated directories `linguist-generated=true` in `.gitattributes`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
