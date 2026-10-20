//! REPO-GIT-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
    MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-06",
    statement: "Auto-delete head branch on merge is enabled",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    evaluation_reason: None,
};
