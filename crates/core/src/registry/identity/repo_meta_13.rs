//! REPO-META-13.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Section, Severity, MERGE_SETTINGS_DISCLOSURE,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-13",
    statement: "Live GitHub metadata matches the declared file",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "`gh repo view` vs file — drift means reconciliation is not running",
    remediation: remediation(
        "align-live-settings",
        "REPO-META-13",
        Lane::OperatorSetting,
        "Align live GitHub metadata to the declared file.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: Some(&MERGE_SETTINGS_DISCLOSURE),
    unbuilt_reason: None,
};
