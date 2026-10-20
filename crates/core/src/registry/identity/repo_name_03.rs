//! REPO-NAME-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-03",
    statement: "A repository in a product family carries the family prefix",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Repository name",
    remediation: remediation(
        "rename-repository-family-prefix",
        "REPO-NAME-03",
        Lane::OperatorSetting,
        "Rename the repository to carry its product family prefix.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
