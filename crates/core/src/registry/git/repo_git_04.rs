//! REPO-GIT-04.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-04",
    statement: "Merge commits are disabled",
    severity: Severity::Advisory,
    section: Section::Git,
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
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
