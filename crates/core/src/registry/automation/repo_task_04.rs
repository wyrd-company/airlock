//! REPO-TASK-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-04",
    statement: "In a monorepo, each release unit has a `taskfile.yml` at its path",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::ReleaseUnitsDeclared,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
