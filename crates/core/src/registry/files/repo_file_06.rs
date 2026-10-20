//! REPO-FILE-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-06",
    statement: "`taskfile.yml` exists, lowercase",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-taskfile",
        "REPO-FILE-06",
        Lane::JudgmentFile,
        "Add a lowercase `taskfile.yml` wired to this repository's toolchain.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
