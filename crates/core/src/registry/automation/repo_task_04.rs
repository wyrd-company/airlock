//! REPO-TASK-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-04",
    statement: "In a monorepo, each release unit has a `taskfile.yml` at its path",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "File presence per `.intentional/config.yml`",
    remediation: remediation(
        "add-release-unit-taskfiles",
        "REPO-TASK-04",
        Lane::JudgmentFile,
        "Add a `taskfile.yml` at each release unit's path.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
