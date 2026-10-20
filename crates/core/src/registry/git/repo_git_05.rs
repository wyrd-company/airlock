//! REPO-GIT-05.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-05",
    statement: "Squash merge is enabled",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`gh repo view --json squashMergeAllowed`",
    remediation: remediation(
        "enable-squash-merge",
        "REPO-GIT-05",
        Lane::OperatorSetting,
        "Enable squash merge in the live repository settings.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
