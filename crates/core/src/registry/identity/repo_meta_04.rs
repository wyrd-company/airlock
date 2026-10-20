//! REPO-META-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-04",
    statement: "The description contains no self-deprecation",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Read it",
    remediation: remediation(
        "remove-description-self-deprecation",
        "REPO-META-04",
        Lane::JudgmentFile,
        "Rewrite the declared description without self-deprecation.",
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
