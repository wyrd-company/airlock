//! REPO-TASK-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-01",
    statement: "`test`, `lint`, `format`, and `check` tasks exist",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`task --list-all`",
    remediation: remediation(
        "add-core-tasks",
        "REPO-TASK-01",
        Lane::JudgmentFile,
        "Add `test`, `lint`, `format`, and `check` tasks wired to this repository's toolchain.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
