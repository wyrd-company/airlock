//! REPO-TASK-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-05",
    statement: "Every include sets `dir:`",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Root `taskfile.yml`",
    remediation: remediation(
        "set-include-dirs",
        "REPO-TASK-05",
        Lane::DeterministicFile,
        "Set `dir:` on every taskfile include.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
