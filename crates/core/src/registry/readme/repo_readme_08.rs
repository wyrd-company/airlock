//! REPO-README-08.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-08",
    statement: "No license section",
    severity: Severity::Advisory,
    section: Section::Readme,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "remove-license-section",
        "REPO-README-08",
        Lane::JudgmentFile,
        "Remove the README's license section.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
