//! REPO-README-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-05",
    statement: "A repository with a user interface has an animated demo",
    severity: Severity::Advisory,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "add-animated-demo",
        "REPO-README-05",
        Lane::JudgmentFile,
        "Record and embed an animated demo.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
