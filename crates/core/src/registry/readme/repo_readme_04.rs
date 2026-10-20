//! REPO-README-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-04",
    statement: "A quickstart or usage section contains at least one real, runnable example",
    severity: Severity::Blocking,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "write-quickstart-section",
        "REPO-README-04",
        Lane::JudgmentFile,
        "Write a quickstart with at least one real, runnable example.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
