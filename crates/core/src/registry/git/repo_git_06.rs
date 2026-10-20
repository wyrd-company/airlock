//! REPO-GIT-06.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-06",
    statement: "Auto-delete head branch on merge is enabled",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json deleteBranchOnMerge`",
    remediation: remediation(
        "enable-head-branch-auto-delete",
        "REPO-GIT-06",
        Lane::OperatorSetting,
        "Enable auto-delete of head branches on merge.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
