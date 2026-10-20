//! REPO-PROP-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-PROP-03",
    statement: "`.github/repo-settings.yml` declares no custom property values",
    severity: Severity::Blocking,
    section: Section::Classification,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "remove-custom-property-values",
        "REPO-PROP-03",
        Lane::DeterministicFile,
        "Remove custom property values from `.github/repo-settings.yml`.",
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
