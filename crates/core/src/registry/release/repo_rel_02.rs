//! REPO-REL-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-02",
    statement: "A `CHANGELOG.md` exists at each release unit's declared path",
    severity: Severity::Required,
    section: Section::Release,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Compare against `.intentional/config.yml`",
    remediation: remediation(
        "add-unit-changelogs",
        "REPO-REL-02",
        Lane::DeterministicFile,
        "Add a `CHANGELOG.md` skeleton at each release unit's declared path.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
