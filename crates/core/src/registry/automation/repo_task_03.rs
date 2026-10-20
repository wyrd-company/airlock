//! REPO-TASK-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-03",
    statement: "`task check` runs everything CI runs",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Compare taskfile against workflows",
    remediation: remediation(
        "align-check-with-ci",
        "REPO-TASK-03",
        Lane::JudgmentFile,
        "Make `task check` run everything CI runs.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
