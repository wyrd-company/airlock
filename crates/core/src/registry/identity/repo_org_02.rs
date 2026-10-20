//! REPO-ORG-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-ORG-02",
    statement: "A `boblangley` repository that has generalized has been considered for graduation to `wyrd-company`",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Judgment",
    remediation: not_remediable(
        "REPO-ORG-02",
        "Satisfied by a human's considered judgment; there is no artifact to change.",
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
