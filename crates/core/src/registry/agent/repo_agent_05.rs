//! REPO-AGENT-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-05",
    statement: "Generated directories are marked `linguist-generated=true` in `.gitattributes`",
    severity: Severity::Advisory,
    section: Section::Agent,
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
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
