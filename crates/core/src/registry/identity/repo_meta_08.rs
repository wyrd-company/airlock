//! REPO-META-08.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-08",
    statement: "A repository in a product family carries the family topic",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: remediation(
        "add-family-topic",
        "REPO-META-08",
        Lane::JudgmentFile,
        "Add the product family topic to the declared topics.",
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
