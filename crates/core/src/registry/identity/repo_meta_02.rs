//! REPO-META-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-02",
    statement:
        "The description is one sentence, at most 160 characters, and survives truncation at ~80",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "rewrite-description-length",
        "REPO-META-02",
        Lane::JudgmentFile,
        "Rewrite the declared description as one sentence within the length budget.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("A remaining requirement has no compiled check yet"),
};
