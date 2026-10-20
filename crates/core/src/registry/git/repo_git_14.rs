//! REPO-GIT-14.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-14",
    statement: "No secret or variable is named after the task that introduced it",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "Workflow source",
    remediation: remediation(
        "rename-task-named-credentials",
        "REPO-GIT-14",
        Lane::OperatorSetting,
        "Rename secrets and variables after what they are, not the task that introduced them.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
