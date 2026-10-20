//! REPO-FILE-16.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-16",
    statement: "`.github/repo-settings.yml` exists",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-repo-settings",
        "REPO-FILE-16",
        Lane::JudgmentFile,
        "Add `.github/repo-settings.yml` declaring this repository's metadata.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
