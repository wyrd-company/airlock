//! REPO-NAME-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-04",
    statement: "The family prefix and the family topic agree",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Name vs topics",
    remediation: remediation(
        "align-family-prefix-and-topic",
        "REPO-NAME-04",
        Lane::JudgmentFile,
        "Align the declared family topic with the name's family prefix.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
