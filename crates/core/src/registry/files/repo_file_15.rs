//! REPO-FILE-15.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-15",
    statement: "Community health files are inherited from the org rather than duplicated, unless the local copy deliberately differs",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "Compare against the org `.github` repository",
    remediation: remediation(
        "remove-duplicated-health-files",
        "REPO-FILE-15",
        Lane::JudgmentFile,
        "Remove community health files the org already provides, unless the local copy is deliberate.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
