//! REPO-GIT-13.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-13",
    statement: "A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY`",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "Workflow source",
    remediation: remediation(
        "rename-app-credentials",
        "REPO-GIT-13",
        Lane::OperatorSetting,
        "Rename the GitHub App identity to an `<APP>_APP_ID` variable and its private key to an `<APP>_APP_PRIVATE_KEY` secret.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
