//! REPO-META-12.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-12",
    statement: "`.github/repo-settings.yml` declares no `visibility` field",
    severity: Severity::Blocking,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "remove-visibility-field",
        "REPO-META-12",
        Lane::DeterministicFile,
        "Remove the `visibility` field from `.github/repo-settings.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
