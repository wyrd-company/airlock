//! REPO-TASK-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-02",
    statement: "of `build` and `dev` was an explicit decision, and they exist where applicable",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`task --list-all` plus the recorded decision",
    remediation: remediation(
        "decide-build-and-dev-tasks",
        "REPO-TASK-02",
        Lane::JudgmentFile,
        "Decide whether `build` and `dev` apply, and add them where they do.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
