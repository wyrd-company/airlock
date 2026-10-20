//! REPO-FILE-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-01",
    statement: "`README.md` exists",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-readme",
        "REPO-FILE-01",
        Lane::JudgmentFile,
        "Write a `README.md` for this repository.",
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
