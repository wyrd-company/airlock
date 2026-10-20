//! REPO-FILE-11.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-11",
    statement: "`AGENTS.md` exists",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-agents-file",
        "REPO-FILE-11",
        Lane::JudgmentFile,
        "Write an `AGENTS.md` for this repository.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
