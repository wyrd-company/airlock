//! REPO-GIT-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-01",
    statement: "The default branch is `main`",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json defaultBranchRef`",
    remediation: remediation(
        "set-default-branch-main",
        "REPO-GIT-01",
        Lane::OperatorSetting,
        "Rename the default branch to `main`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
