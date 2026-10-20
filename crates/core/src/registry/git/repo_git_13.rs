//! REPO-GIT-13.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-13",
    statement: "A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY`",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
