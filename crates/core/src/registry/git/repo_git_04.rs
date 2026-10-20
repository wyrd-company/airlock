//! REPO-GIT-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
    MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-04",
    statement: "Merge commits are disabled",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`gh repo view --json mergeCommitAllowed`",
    remediation: remediation(
        "disable-merge-commits",
        "REPO-GIT-04",
        Lane::OperatorSetting,
        "Disable merge commits in the live repository settings.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    evaluation_reason: None,
};
