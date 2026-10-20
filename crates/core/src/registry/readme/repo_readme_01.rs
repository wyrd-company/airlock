//! REPO-README-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-01",
    statement: "Opens with a title and a one-line statement of what it is",
    severity: Severity::Advisory,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "write-readme-opening",
        "REPO-README-01",
        Lane::JudgmentFile,
        "Open the README with a title and a one-line statement of what it is.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
