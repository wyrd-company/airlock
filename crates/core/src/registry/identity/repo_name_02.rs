//! REPO-NAME-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-02",
    statement: "A dotted name is used only where the repository is a deployable site and the name is its hostname",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Repository name",
    remediation: remediation(
        "rename-repository-undotted",
        "REPO-NAME-02",
        Lane::OperatorSetting,
        "Rename the repository so only a deployable site named for its hostname carries a dot.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
