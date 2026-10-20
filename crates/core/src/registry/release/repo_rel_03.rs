//! REPO-REL-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-03",
    statement: "A multi-unit repository has no root aggregate changelog",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "remove-root-changelog",
        "REPO-REL-03",
        Lane::DeterministicFile,
        "Remove the root aggregate changelog.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
